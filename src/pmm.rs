//! Where boot's general-purpose memory lives ([RFC-0039](../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)):
//! the largest run of RAM the device tree leaves free, outside the firmware's reservations, the device tree itself and
//! this image's two megapages, megapage-aligned because `Untyped::with_memory` needs it. [`crate::platform::discover`]
//! sets it, once, before any loader runs; nothing here is assumed about the machine.
//!
//! [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md) moved real physical-memory
//! bookkeeping into `lantern-kernel` (`Untyped::bump`): each loader seeds one memory-backed `Untyped` from this range.

use core::sync::atomic::{AtomicUsize, Ordering};

static BASE: AtomicUsize = AtomicUsize::new(0);
static END: AtomicUsize = AtomicUsize::new(0);

/// Records the range. Called once, by `platform::discover`.
pub fn set(base: usize, end: usize) {
    BASE.store(base, Ordering::Relaxed);
    END.store(end, Ordering::Relaxed);
}

fn checked(v: usize) -> usize {
    assert!(v != 0, "boot's memory wasn't set: platform::discover must run first");
    v
}

/// The first byte of general memory.
pub fn general_memory_base() -> usize {
    checked(BASE.load(Ordering::Relaxed))
}

/// One past its last byte.
pub fn general_memory_end() -> usize {
    checked(END.load(Ordering::Relaxed))
}
