//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s broker demo
//! (`../src/broker_demo/loader.rs`), the same ELF-loading mechanism
//! `hello-service` proves (RFC-0008/ADR-0012).
//!
//! Plays the **broker** half of [RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)'s
//! confined-capability-broker demo.
//!
//! **This runs [`lantern_capabilities::Broker`]'s own code** — since
//! 2026-09-05, via that crate's [`Abi`](lantern_capabilities::Abi) backend
//! ([RFC-0018](../../lantern-rfcs/rfcs/0018-confined-execution-port.md) /
//! [ADR-0022](../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)),
//! not a hand-rolled reimplementation of the sequence. `lantern-capabilities`
//! is pulled in with `default-features = false`, so only `lantern-abi` is
//! linked — nothing from the TCB. This closes the gap
//! `lantern-capabilities/STATUS.md` flagged: the broker's *actual* logic
//! (`mint`'s GRANT check + badge bookkeeping, `grant_via_reply`) now executes
//! for real under confined U-mode `ecall`s on QEMU.
//!
//! `SELF_CNODE_CPTR`/`ENDPOINT_CPTR`/`RESOURCE_CPTR`/`SCRATCH_CPTR` are
//! conventions the loader and this binary agree on without reading each other's
//! source. `../broker-client/` plays the other half.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::sys;
use lantern_capabilities::{Abi, Broker, Rights};

lantern_abi::entry!(run);

/// Root's own CNode capability, granted here at boot (`CNodeInvoke::CopyCross`
/// from the loader) so the broker can invoke `Mint` on itself.
const SELF_CNODE_CPTR: usize = 0;
/// The endpoint this program and `broker-client` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// The capability this broker administers and grants attenuated copies of — a
/// `Notification`, granted here at boot with full rights, standing in for
/// whatever a real Phase 2 service would hold (a file, a key).
const RESOURCE_CPTR: usize = 2;
/// Scratch slot the minted, badged copy lands in before `Reply` transfers it.
const SCRATCH_CPTR: usize = 3;

fn run(_arg0: usize) -> ! {
    let mut broker = Broker::new(SELF_CNODE_CPTR);
    let mut backend = Abi;

    // Rendezvous with the client's `Call` (it registered its own reply-leg
    // destination slot; this broker just needs to receive, then reply).
    let _ = sys::recv(ENDPOINT_CPTR);

    // `Broker::mint`: its own `Rights::GRANT` policy check, then a real
    // `CNodeInvoke::Mint` (via `Abi` -> `ecall`), then it records the badge in
    // its revocation table. READ | WRITE | GRANT — enough for the client to
    // prove the capability is real by `Signal`-ing it (Signal needs WRITE).
    let minted = broker.mint(
        &mut backend,
        RESOURCE_CPTR,
        SCRATCH_CPTR,
        Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
    );

    if minted.is_ok() {
        // `Broker::grant_via_reply`: a real `Reply` with the capability
        // attached (`tag.extra_caps == 1`), landing in whatever slot the
        // client registered on its `Call`.
        let _ = broker.grant_via_reply(&mut backend, SCRATCH_CPTR, (111, 222));
    }

    // Job done once the reply delivers.
    loop {
        core::hint::spin_loop();
    }
}
