//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s store demo
//! (`../src/store_demo/loader.rs`).
//!
//! Runs a **real, confined [`lantern_filesystem::Store`]** — the RFC-0018/
//! ADR-0022 Part 1 confined-service port, applied to the store for the first
//! time (`../keystore-service/` already proved the pattern for `Keystore`).
//! This is the first demo program with *two* distinct IPC relationships at
//! once, exactly the "middle service" shape ADR-0022 describes:
//!
//! 1. **A keystore *client* leg** — registers with `../keystore-service/`
//!    exactly the way `../keystore-client/` does (`Call`, registering its own
//!    reply destination), receiving a badge scoped to ENCRYPT|DECRYPT on that
//!    demo's one AEAD key. This badge/`Channel` pair becomes a
//!    [`lantern_filesystem::cipher::ChannelCipher`] — `Store`'s own AEAD
//!    operations reach the key over *real IPC*, not a direct `&Keystore`
//!    reference, closing the gap `lantern-filesystem/STATUS.md` named after
//!    the `Cipher` trait redesign.
//! 2. **A store *service* leg** — a live `Broker::mint`+`grant_via_reply`
//!    file-access grant round for its own client (`../store-client/`), then
//!    an RFC-0019/ADR-0024 READ/WRITE `Recv` loop over a *second*,
//!    independent shared `Frame` — `lantern_filesystem::wire::handle_request`
//!    does the actual parsing/dispatch (reviewed and unit-tested in
//!    `lantern-filesystem` itself, not re-derived here).
//!
//! Two shared `Frame`s, two different virtual addresses in this program's own
//! single VSpace (`KS_FRAME_VADDR`/`CLIENT_FRAME_VADDR`) — `Channel` has no
//! concept of "the" frame, each instance just wraps whichever `(endpoint,
//! frame)` pair it was constructed against.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::Channel;
use lantern_abi::sys;
use lantern_capabilities::Abi;
use lantern_filesystem::cipher::ChannelCipher;
use lantern_filesystem::{wire, FileOps, Store};

lantern_abi::entry!(run);

/// Root's own CNode capability, granted at boot so this store can invoke
/// `Mint` on itself — matches `keystore-service`'s identical convention.
const SELF_CNODE_CPTR: usize = 0;
/// The endpoint this program and `keystore-service` both hold a capability
/// to — this program's *client* leg.
const KS_ENDPOINT_CPTR: usize = 1;
/// Where `keystore-service`'s granted, badged capability lands — this
/// program's actual `Channel` to it afterward.
const KS_DEST_CPTR: usize = 2;
/// The endpoint this program and `store-client` both hold a capability to —
/// this program's *service* leg, also `Broker::mint`'s attenuation source
/// (see `keystore-service`'s module doc for why the retained authority and
/// the mint source are the same capability).
const CLIENT_ENDPOINT_CPTR: usize = 3;
/// Scratch slot the minted, badged file-access copy lands in before `Reply`
/// transfers it to `store-client`.
const SCRATCH_CPTR: usize = 4;
/// Where the loader mapped this program's half of the `keystore-service`
/// shared `Frame` — must match `keystore-service`'s own `FRAME_VADDR`.
const KS_FRAME_VADDR: usize = 0x9000_0000;
/// Where the loader mapped this program's half of the `store-client` shared
/// `Frame` — a *different* virtual address in this program's own VSpace than
/// [`KS_FRAME_VADDR`] (two independent physical Frames, two mappings) — must
/// match `store-client`'s own `FRAME_VADDR`.
const CLIENT_FRAME_VADDR: usize = 0x9001_0000;

/// Large enough for this demo's small READ/WRITE payloads — see
/// `keystore-service`'s identical constant for the general sizing rule.
const REQUEST_CAP: usize = 256;

fn run(_arg0: usize) -> ! {
    // Client leg: register with keystore-service, registering our own
    // reply-leg destination (broker-client's exact convention).
    let _ = sys::call_with_reply_slot(KS_ENDPOINT_CPTR, KS_DEST_CPTR, [0, 0]);
    // SAFETY: the loader mapped `KS_FRAME_VADDR..+FRAME_LEN` read/write into
    // this program's own VSpace before its first instruction ran
    // (`store_demo/loader.rs`'s first `map_shared_frame` call).
    let mut ks_channel = unsafe { Channel::new(KS_DEST_CPTR, KS_FRAME_VADDR as *mut u8) };

    let mut store = Store::new(SELF_CNODE_CPTR);
    let file = store.create().expect("fresh Store always has room for its first file");

    let mut backend = Abi;
    // Service leg: one client Call's, registering its own reply-leg
    // destination; grant it READ|WRITE on the one file this demo creates.
    let _ = sys::recv(CLIENT_ENDPOINT_CPTR);
    if let Ok(()) = store
        .request_file_access(&mut backend, file, FileOps::READ.union(FileOps::WRITE), CLIENT_ENDPOINT_CPTR, SCRATCH_CPTR)
        .and_then(|_badge| store.deliver_grant_via_reply(&mut backend, SCRATCH_CPTR, (0, 0)))
    {
        // SAFETY: as above, for `CLIENT_FRAME_VADDR` (the loader's *second*
        // `map_shared_frame` call).
        let mut client_channel = unsafe { Channel::new(CLIENT_ENDPOINT_CPTR, CLIENT_FRAME_VADDR as *mut u8) };
        loop {
            let Ok(received) = sys::recv(CLIENT_ENDPOINT_CPTR) else { continue };
            let mut request = [0u8; REQUEST_CAP];
            if let Ok((op, len)) = client_channel.recv_request(received, &mut request) {
                // The keystore-service leg: Store's own encrypt/decrypt reach
                // the AEAD key over real IPC, not a direct &Keystore call.
                let mut cipher = ChannelCipher::new(&mut ks_channel);
                let mut reply = [0u8; REQUEST_CAP];
                let (status, reply_len) =
                    wire::handle_request(&mut store, &mut cipher, received.badge, op, &request[..len], &mut reply);
                let _ = client_channel.reply(status, &reply[..reply_len]);
            }
            // `recv_request`'s `Err` path has already sent `INVALID` itself.
        }
    }

    loop {
        core::hint::spin_loop();
    }
}
