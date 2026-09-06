//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s broker demo
//! (`../src/broker_demo/loader.rs`).
//!
//! Plays the **client** half of [RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)'s
//! confined-capability-broker demo: `Call`s `../broker-service/`, registering
//! its own destination slot for a capability the `Reply` might attach
//! (`tag.extra_caps == 2` — `lantern_kernel::ipc::call`'s reply-leg
//! convention), then — the actual proof this is a *real*, functional capability
//! and not just bytes that landed in a CSpace slot — invokes `Signal` on it. A
//! forged or empty slot would fail that `Signal` with `InvalidCapability`; only
//! a genuinely transferred, `WRITE`-rights `Notification` capability succeeds.
//!
//! **Now built on [`lantern_abi`]** ([RFC-0018](../../lantern-rfcs/rfcs/0018-confined-execution-port.md) /
//! [ADR-0022](../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)) —
//! `sys::call_with_reply_slot` and `sys::signal` replace the hand-rolled `ecall`
//! and tag packing; `_start` and the `#[panic_handler]` come from the crate.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::sys;

lantern_abi::entry!(run);

/// The endpoint this program and `broker-service` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// Where this program registers the granted capability should land — its own
/// choice, unrelated to `broker-service`'s own `SCRATCH_CPTR`/`RESOURCE_CPTR`
/// numbering (different CSpaces).
const DEST_CPTR: usize = 2;

fn run(_arg0: usize) -> ! {
    // Call the broker, registering DEST_CPTR as our own reply-leg destination
    // (tag.extra_caps == 2 — no outbound transfer this call, just "here's where
    // a capability the Reply attaches should land").
    let _ = sys::call_with_reply_slot(ENDPOINT_CPTR, DEST_CPTR, [0, 0]);

    // Prove the granted capability is real and functional, not just bytes that
    // happened to land in DEST_CPTR: Signal it. This only succeeds if DEST_CPTR genuinely
    // holds a WRITE-rights Notification capability — `lantern-boot`'s broker-demo
    // trap handler narrates the real result straight from S-mode as this
    // dispatches.
    let _ = sys::signal(DEST_CPTR);

    loop {
        core::hint::spin_loop();
    }
}
