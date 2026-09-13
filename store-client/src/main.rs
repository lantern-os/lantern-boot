//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s store demo
//! (`../src/store_demo/loader.rs`).
//!
//! Plays the client half of the confined [`lantern_filesystem::Store`] demo —
//! a stand-in for a real `lantern-runtime` reaching a store-service, using
//! exactly the wire op codes `lantern_filesystem::wire` already exposes.
//!
//! 1. `Call`s `../store-service/`, registering `DEST_CPTR` as its reply-leg
//!    destination (`keystore-client`'s exact convention) — the store-service
//!    mints and hands back a badged capability scoped to READ|WRITE on its
//!    one demo file.
//! 2. Uses that granted capability to `Channel::call` a WRITE, then a READ,
//!    over the shared `Frame` — a real round trip through a confined store
//!    (whose own AEAD operations, in turn, round-trip through a confined
//!    keystore — see `../store-service/src/main.rs`'s module doc), not an
//!    in-process call.
//! 3. Independently verifies the read-back content matches what it wrote
//!    (the real proof, same shape as `keystore-client`'s own check) and
//!    signals one of two distinguishable notifications.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{status, Channel};
use lantern_abi::sys;
use lantern_filesystem::wire;

lantern_abi::entry!(run);

/// The endpoint this program and `store-service` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// Where the store-service's granted, badged capability lands.
const DEST_CPTR: usize = 2;
/// Signalled iff the WRITE→READ round trip matched what this client itself
/// wrote.
const SUCCESS_CPTR: usize = 3;
/// Signalled otherwise, so a mismatch is an observable, differentiated
/// outcome rather than silence.
const FAILURE_CPTR: usize = 4;
/// Where the loader mapped this program's half of the shared `Frame` — must
/// match `store-service`'s own `CLIENT_FRAME_VADDR` constant.
const FRAME_VADDR: usize = 0x9000_0000;

const CONTENT: &[u8] = b"a confined store secret, encrypted by a confined keystore";

fn run(_arg0: usize) -> ! {
    // Phase 1: ask for access, registering DEST_CPTR as the reply-leg
    // destination for the badged capability the store-service grants.
    let _ = sys::call_with_reply_slot(ENDPOINT_CPTR, DEST_CPTR, [0, 0]);

    // Phase 2: use the granted, badged capability to reach the same
    // store-service over the RFC-0019 wire protocol.
    //
    // SAFETY: the loader mapped `FRAME_VADDR..+FRAME_LEN` read/write into
    // this program's own VSpace before its first instruction ran.
    let mut channel = unsafe { Channel::new(DEST_CPTR, FRAME_VADDR as *mut u8) };

    let matched = round_trip(&mut channel).unwrap_or(false);
    let _ = sys::signal(if matched { SUCCESS_CPTR } else { FAILURE_CPTR });

    loop {
        core::hint::spin_loop();
    }
}

/// WRITEs [`CONTENT`], then READs it back, both through the confined
/// store-service — `None` on any wire-level error (a malformed buffer, a
/// `Channel` failure); `Some(false)` on a clean but mismatched round trip.
fn round_trip(channel: &mut Channel) -> Option<bool> {
    let mut write_reply = [0u8; 16];
    let (write_status, _write_len) = channel.call(wire::OP_WRITE, CONTENT, &mut write_reply).ok()?;
    if write_status != status::OK {
        return Some(false);
    }

    let mut read_reply = [0u8; 128];
    let (read_status, read_len) = channel.call(wire::OP_READ, &[], &mut read_reply).ok()?;
    if read_status != status::OK {
        return Some(false);
    }

    Some(&read_reply[..read_len] == CONTENT)
}
