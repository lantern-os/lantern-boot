//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s keystore demo
//! (`../src/keystore_demo/loader.rs`).
//!
//! Runs a **real, confined [`lantern_crypto::Keystore`]** — the RFC-0018/
//! ADR-0022 Part 1 confined-service port, applied to the keystore for the
//! first time (`broker-service` already proved the pattern for the generic
//! [`lantern_capabilities::Broker`] itself). Two phases:
//!
//! 1. **One live access-grant round** — `Recv`s a client's `Call`
//!    (registering its own reply destination, `broker-client`'s exact
//!    convention), then `Keystore::request_key_access` +
//!    `Keystore::deliver_grant_via_reply` (via the confined [`Abi`] backend —
//!    real `ecall`s, `Broker::mint`'s own `Rights::GRANT` check included)
//!    mint and hand over a badge scoped to this demo's one AEAD key. Stands
//!    in for the real launch-binder flow
//!    ([RFC-0015](../../lantern-rfcs/rfcs/0015-capability-manifest-format.md)/`lantern-shell`,
//!    explicitly out of ADR-0022's scope) — what this demo actually exists to
//!    prove is Phase 2, not this grant step (already proven separately by
//!    `broker_demo`).
//! 2. **An [RFC-0019](../../lantern-rfcs/rfcs/0019-confined-service-call-protocol.md)/
//!    [ADR-0024](../../lantern-rfcs/adr/0024-confined-service-call-protocol.md)
//!    `Recv` loop** serving SIGN/ENCRYPT/DECRYPT over
//!    [`lantern_abi::frame::Channel`] and a real shared `Frame`
//!    ([ADR-0022](../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
//!    Part 2) — `lantern_crypto::wire::handle_request` does the actual
//!    parsing/dispatch (reviewed and unit-tested in `lantern-crypto` itself,
//!    not re-derived here). Both phases use the **same** endpoint: the
//!    client's granted capability is a badged copy of it (`Broker::mint`
//!    attenuates from `ENDPOINT_CPTR` itself, not a separate stand-in
//!    resource — this program's own retained authority *is* the thing being
//!    scoped and handed out, the realistic shape ADR-0022 describes).

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::Channel;
use lantern_abi::sys;
use lantern_capabilities::Abi;
use lantern_crypto::{KeyOps, Keystore};

lantern_abi::entry!(run);

/// Root's own CNode capability, granted here at boot (`CNodeInvoke::CopyCross`
/// from the loader) so the keystore can invoke `Mint` on itself — matches
/// `broker-service`'s identical convention.
const SELF_CNODE_CPTR: usize = 0;
/// The endpoint both this program and `keystore-client` hold a capability
/// to — also `Broker::mint`'s attenuation source (see the module doc).
const ENDPOINT_CPTR: usize = 1;
/// Scratch slot the minted, badged copy lands in before `Reply` transfers it.
const SCRATCH_CPTR: usize = 3;
/// Where the loader mapped this program's half of the shared `Frame` — must
/// match `keystore-client`'s own constant.
const FRAME_VADDR: usize = 0x9000_0000;

/// Demo-only fixed key material. A real deployment sources this from a
/// hardware root of trust once `lantern-hal` has one — ADR-0011's "OS CSPRNG
/// seeded from hardware entropy" is still `lantern-crypto/STATUS.md`'s
/// "Blocked on"; `Keystore::generate_aead_key` already takes caller-supplied
/// bytes for exactly this reason (this crate's own top-level doc).
const DEMO_AEAD_SEED: [u8; 32] = [0x42; 32];

/// Large enough for this demo's small ENCRYPT/DECRYPT payloads; a real
/// service sizes this per its own worst-case reassembled argument
/// (RFC-0019's "a fixed maximum reassembled argument size per op").
const REQUEST_CAP: usize = 256;

fn run(_arg0: usize) -> ! {
    let mut keystore = Keystore::new(SELF_CNODE_CPTR);
    let key = keystore.generate_aead_key(DEMO_AEAD_SEED).unwrap();
    let mut backend = Abi;

    // Phase 1: one client Call's, registering its own reply-leg destination;
    // grant it ENCRYPT|DECRYPT on the one demo key.
    let _ = sys::recv(ENDPOINT_CPTR);
    if let Ok(()) = keystore
        .request_key_access(&mut backend, key, KeyOps::ENCRYPT.union(KeyOps::DECRYPT), ENDPOINT_CPTR, SCRATCH_CPTR)
        .and_then(|_badge| keystore.deliver_grant_via_reply(&mut backend, SCRATCH_CPTR, (0, 0)))
    {
        // Phase 2: serve RFC-0019 wire requests on the same endpoint — the
        // client's granted capability is a badged copy of it.
        //
        // SAFETY: the loader mapped `FRAME_VADDR..+FRAME_LEN` read/write into
        // this program's own VSpace before its first instruction ran
        // (`keystore_demo/loader.rs`'s `map_shared_frame` call).
        let mut channel = unsafe { Channel::new(ENDPOINT_CPTR, FRAME_VADDR as *mut u8) };
        loop {
            let Ok(received) = sys::recv(ENDPOINT_CPTR) else { continue };
            let mut request = [0u8; REQUEST_CAP];
            if let Ok((op, len)) = channel.recv_request(received, &mut request) {
                let mut reply = [0u8; REQUEST_CAP];
                let (status, reply_len) =
                    lantern_crypto::wire::handle_request(&keystore, received.badge, op, &request[..len], &mut reply);
                let _ = channel.reply(status, &reply[..reply_len]);
            }
            // `recv_request`'s `Err` path has already sent `INVALID` itself.
        }
    }

    loop {
        core::hint::spin_loop();
    }
}
