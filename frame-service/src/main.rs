//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s frame demo
//! (`../src/frame_demo/loader.rs`).
//!
//! Plays the **service** half of
//! [RFC-0019](../../lantern-rfcs/rfcs/0019-confined-service-call-protocol.md)/
//! [ADR-0024](../../lantern-rfcs/adr/0024-confined-service-call-protocol.md)'s
//! shared-`Frame` framing demo — the first real, confined, under-QEMU proof
//! that [`lantern_abi::frame::Channel`] moves bytes through an actual shared
//! page ([ADR-0022](../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
//! Part 2), not just a host-side unit test against a `Vec<u8>` buffer.
//!
//! `Recv`s one request, reassembles it via [`Channel::recv_request`]
//! (single-chunk here — the request is 11 bytes, nowhere near
//! `FRAME_PAYLOAD`), performs a trivial, real per-byte transform (bitwise
//! NOT — simple enough to independently recompute, real enough that an
//! aliased/mis-copied buffer would visibly fail it), and replies via
//! [`Channel::reply`]. `ENDPOINT_CPTR`/`FRAME_VADDR` are conventions the
//! loader and this binary agree on without reading each other's source;
//! `../frame-client/` plays the other half.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{status, Channel};
use lantern_abi::sys;

lantern_abi::entry!(run);

/// The endpoint this program and `frame-client` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// Where the loader mapped this program's half of the shared `Frame` — must
/// match `frame-client/src/main.rs`'s own `FRAME_VADDR` and
/// `../src/frame_demo/loader.rs`'s `map_shared_frame` call.
const FRAME_VADDR: usize = 0x9000_0000;

/// Large enough for this demo's fixed 11-byte request; real services size
/// this per their own worst-case reassembled argument (RFC-0019's "a fixed
/// maximum reassembled argument size per op").
const REQUEST_CAP: usize = 64;

fn run(_arg0: usize) -> ! {
    // SAFETY: the loader mapped `FRAME_VADDR..+FRAME_LEN` read/write into
    // this program's own VSpace before its first instruction ran
    // (`frame_demo/loader.rs`'s `map_shared_frame` call).
    let mut channel = unsafe { Channel::new(ENDPOINT_CPTR, FRAME_VADDR as *mut u8) };

    let received = sys::recv(ENDPOINT_CPTR).unwrap();
    let mut request = [0u8; REQUEST_CAP];
    if let Ok((_op, len)) = channel.recv_request(received, &mut request) {
        let mut reply = [0u8; REQUEST_CAP];
        for i in 0..len {
            reply[i] = !request[i];
        }
        let _ = channel.reply(status::OK, &reply[..len]);
    }
    // `recv_request`'s `Err` path has already sent `INVALID` itself.

    loop {
        core::hint::spin_loop();
    }
}
