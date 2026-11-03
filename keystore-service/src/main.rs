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
//!
//! **`arg0` picks which one key this instance holds and grants** — the one
//! piece of launch-time configuration it takes: [`PROFILE_AEAD`] (an AEAD key,
//! ENCRYPT|DECRYPT; `keystore_demo`/`store_demo`) or [`PROFILE_SIGNING`] (an
//! Ed25519 key, SIGN only; `runtime_demo`, where the client is a confined
//! `lantern-runtime` hosting a guest component that only ever signs). The
//! [`grant::BINDER_LAUNCHED`] flag drops phase 1: this instance then grants only
//! over [RFC-0020](../../lantern-rfcs/rfcs/0020-launch-binder.md)'s `GRANT`, from
//! the launch binder, and never to its first caller. In every mode, a `GRANT`
//! from anyone else is refused `ACCESS`.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{self, status, Channel, Interloper};
use lantern_abi::grant::{self, Incoming};
use lantern_abi::sys::{self, Received};
use lantern_capabilities::Abi;
use lantern_crypto::{KeyId, KeyOps, Keystore};

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

/// Demo-only fixed Ed25519 seed, same caveat as [`DEMO_AEAD_SEED`].
const DEMO_SIGNING_SEED: [u8; 32] = [0x24; 32];

/// `arg0` values — see the module doc. Must match each loader's own constant.
const PROFILE_AEAD: usize = 0;
const PROFILE_SIGNING: usize = 1;

/// Large enough for this demo's small ENCRYPT/DECRYPT payloads; a real
/// service sizes this per its own worst-case reassembled argument
/// (RFC-0019's "a fixed maximum reassembled argument size per op").
const REQUEST_CAP: usize = 256;

fn run(arg0: usize) -> ! {
    let mut keystore = Keystore::new(SELF_CNODE_CPTR);
    let (key, ops) = match arg0 & !grant::BINDER_LAUNCHED {
        PROFILE_SIGNING => (keystore.generate_signing_key(DEMO_SIGNING_SEED), KeyOps::SIGN),
        PROFILE_AEAD => (keystore.generate_aead_key(DEMO_AEAD_SEED), KeyOps::ENCRYPT.union(KeyOps::DECRYPT)),
        _ => panic!("keystore-service: unknown arg0 profile"),
    };
    let key = key.unwrap();
    let mut backend = Abi;

    // Phase 1: one client Call's, registering its own reply-leg destination;
    // grant it `ops` on the one demo key.
    if arg0 & grant::BINDER_LAUNCHED == 0 {
        let _ = sys::recv(ENDPOINT_CPTR);
        let granted = keystore
            .request_key_access(&mut backend, key, ops, ENDPOINT_CPTR, SCRATCH_CPTR)
            .and_then(|_badge| keystore.deliver_grant_via_reply(&mut backend, SCRATCH_CPTR, (0, 0)));
        if granted.is_err() {
            loop {
                core::hint::spin_loop();
            }
        }
        // `Reply` copies a transferred capability; a later `GRANT` needs this slot empty.
        let _ = sys::cnode::delete(SELF_CNODE_CPTR, SCRATCH_CPTR);
    }

    // Phase 2: serve RFC-0019 wire requests on the same endpoint — the
    // client's granted capability is a badged copy of it.
    //
    // SAFETY: the loader mapped `FRAME_VADDR..+FRAME_LEN` read/write into
    // this program's own VSpace before its first instruction ran
    // (`keystore_demo/loader.rs`'s `map_shared_frame` call).
    let mut channel = unsafe { Channel::new(ENDPOINT_CPTR, FRAME_VADDR as *mut u8) };
    loop {
        let Ok(received) = sys::recv(ENDPOINT_CPTR) else { continue };
        match grant::classify(&received) {
            Incoming::Data => {
                let mut request = [0u8; REQUEST_CAP];
                let mut others = Others { keystore: &mut keystore, backend: &mut backend };
                if let Ok((op, len)) = channel.recv_request(received, &mut request, &mut others) {
                    let mut reply = [0u8; REQUEST_CAP];
                    let (status, reply_len) =
                        lantern_crypto::wire::handle_request(&keystore, received.badge, op, &request[..len], &mut reply);
                    let mut others = Others { keystore: &mut keystore, backend: &mut backend };
                    let _ = channel.reply(status, &reply[..reply_len], received.badge, &mut others);
                }
                // `recv_request`'s `Err` path has already sent `INVALID` itself.
            }
            _ => Others { keystore: &mut keystore, backend: &mut backend }.serve(received),
        }
    }
}

/// Everything that isn't the data client: served the same way whether this program is idle or
/// waiting on a client's next chunk (RFC-0021). All of it stays off the shared `Frame`.
struct Others<'a> {
    keystore: &'a mut Keystore,
    backend: &'a mut Abi,
}

impl Interloper for Others<'_> {
    fn serve(&mut self, received: Received) {
        match grant::classify(&received) {
            Incoming::Grant { object, ops } => serve_grant(self.keystore, self.backend, object, ops),
            Incoming::Revoke { badge } => {
                let status = if self.keystore.revoke_access(badge).is_ok() { status::OK } else { status::INVALID };
                let _ = grant::reply_status(status);
            }
            Incoming::ForgedGrant => {
                let _ = grant::reply_status(status::ACCESS);
            }
            Incoming::Data => frame::reply_busy(),
        }
    }

    fn still_allowed(&self, badge: u64) -> bool {
        !self.keystore.is_revoked(badge)
    }
}

/// RFC-0020's `GRANT`: mint exactly `ops` on `object` and hand the badge back. The
/// checks that matter (the key exists, isn't destroyed, and supports `ops`) are
/// `request_key_access`'s own.
fn serve_grant(keystore: &mut Keystore, backend: &mut Abi, object: usize, ops: usize) {
    let request = u16::try_from(object)
        .ok()
        .zip(u8::try_from(ops).ok().filter(|&bits| bits != 0).and_then(KeyOps::from_bits));
    let Some((object, ops)) = request else {
        let _ = grant::reply_status(status::INVALID);
        return;
    };
    let granted = keystore
        .request_key_access(backend, KeyId::from_raw(object), ops, ENDPOINT_CPTR, SCRATCH_CPTR)
        .and_then(|badge| keystore.deliver_grant_via_reply(backend, SCRATCH_CPTR, (status::OK as usize, badge as usize)));
    if granted.is_err() {
        let _ = grant::reply_status(status::INVALID);
    }
    // `Reply` copies a transferred capability; the next `GRANT` needs this slot empty.
    let _ = sys::cnode::delete(SELF_CNODE_CPTR, SCRATCH_CPTR);
}
