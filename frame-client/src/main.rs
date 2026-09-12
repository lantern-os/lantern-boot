//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s frame demo
//! (`../src/frame_demo/loader.rs`).
//!
//! Plays the **client** half of
//! [RFC-0019](../../lantern-rfcs/rfcs/0019-confined-service-call-protocol.md)/
//! [ADR-0024](../../lantern-rfcs/adr/0024-confined-service-call-protocol.md)'s
//! shared-`Frame` framing demo: [`Channel::call`]s `../frame-service/` with a
//! fixed 11-byte request, then independently recomputes the expected reply
//! (the same bitwise-NOT the service applies) and compares — the real proof
//! this is a genuine round trip through shared memory and not, say, a
//! service that just echoes the request back unmodified. `Signal`s
//! `SUCCESS_CPTR` iff the reply matches; `FAILURE_CPTR` otherwise (so the
//! demo always produces an observable, differentiated result under QEMU
//! rather than silently hanging on a mismatch).

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{status, Channel};
use lantern_abi::sys;

lantern_abi::entry!(run);

/// The endpoint this program and `frame-service` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// Signalled iff the reply matched this client's own independently computed
/// expectation — the real proof, same shape as `broker-client`'s `Signal` on
/// a genuinely transferred capability.
const SUCCESS_CPTR: usize = 2;
/// Signalled otherwise, so a mismatch is an observable, differentiated
/// outcome rather than silence.
const FAILURE_CPTR: usize = 3;
/// Where the loader mapped this program's half of the shared `Frame` — must
/// match `frame-service`'s own constant.
const FRAME_VADDR: usize = 0x9000_0000;

const REQUEST: &[u8] = b"hello frame";
/// Arbitrary — this demo has only one operation, so the exact value carries
/// no dispatch meaning, only RFC-0019's redundant-tag-vs-header check.
const OP: u16 = 7;

fn run(_arg0: usize) -> ! {
    // SAFETY: as `frame-service`'s — the loader mapped this before either
    // program's first instruction ran.
    let mut channel = unsafe { Channel::new(ENDPOINT_CPTR, FRAME_VADDR as *mut u8) };

    let mut reply = [0u8; REQUEST.len()];
    let outcome = channel.call(OP, REQUEST, &mut reply);

    let mut expected = [0u8; REQUEST.len()];
    for (i, byte) in REQUEST.iter().enumerate() {
        expected[i] = !byte;
    }

    let matched = matches!(outcome, Ok((s, len)) if s == status::OK && len == REQUEST.len() && reply == expected);
    let _ = sys::signal(if matched { SUCCESS_CPTR } else { FAILURE_CPTR });

    loop {
        core::hint::spin_loop();
    }
}
