//! A trivial physical frame allocator: bump-allocates 4 KiB pages from a static,
//! page-aligned arena.
//!
//! **Phase 1 stand-in for real physical memory.** Real discovery from the device
//! tree `boot_main` already receives is still deferred (`STATUS.md`) — this arena
//! lives in `lantern-boot`'s own `.bss`, at whatever physical address the linker
//! placed it (usable directly as a physical address: this crate identity-maps
//! everything, see `paging.rs`). No reclaim, ever — Phase 1 never frees a frame
//! once allocated, matching `lantern-kernel`'s `Untyped` object's own "no reclaim"
//! simplification. Frames are handed out already zeroed for free: `.bss` starts
//! zero (`entry.rs` clears it before `boot_main` runs) and, with no reclaim, no
//! frame is ever handed out a second time to need re-zeroing.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use lantern_hal::RISCV64_PAGE_SIZE;

/// 1 MiB — generous for a two-thread demo's page tables plus stacks, nowhere near
/// a real memory budget.
const FRAME_COUNT: usize = 256;

#[repr(C, align(4096))]
struct Arena([[u8; RISCV64_PAGE_SIZE]; FRAME_COUNT]);

struct ArenaCell(UnsafeCell<Arena>);
// SAFETY: each frame index is handed to exactly one caller (`NEXT_FRAME`'s
// `fetch_add` is atomic and monotonic, and Phase 1 is single-hart/non-reentrant
// besides — ADR-0010), so there is never a second live reference to the same frame.
unsafe impl Sync for ArenaCell {}

static ARENA: ArenaCell = ArenaCell(UnsafeCell::new(Arena([[0; RISCV64_PAGE_SIZE]; FRAME_COUNT])));
static NEXT_FRAME: AtomicUsize = AtomicUsize::new(0);

/// Allocates one zeroed 4 KiB physical page, returning its physical address.
/// Used for page-table frames (root/L1) — [`alloc_stack_region`] below is what
/// hands out thread stacks.
///
/// Panics if the arena is exhausted — boot-time setup code isn't bound by
/// ADR-0008's "no syscall panics" rule (this runs before there's a kernel to
/// panic *in*), and a demo running out of a 1 MiB arena is a configuration bug
/// worth an immediate, loud failure, not a silently wrong page table.
pub fn alloc_frame() -> usize {
    let index = NEXT_FRAME.fetch_add(1, Ordering::Relaxed);
    assert!(index < FRAME_COUNT, "physical frame arena exhausted");
    // SAFETY: see `ArenaCell`'s doc — this index is exclusively ours.
    let arena = unsafe { &mut *ARENA.0.get() };
    arena.0[index].as_mut_ptr() as usize
}

/// Where `linker.ld` ends the two megapages it reserves for the kernel image and
/// `.user_text` (`0x8020_0000` + 2x [`lantern_hal::RISCV64_MEGAPAGE_SIZE`]).
/// Hardcoded rather than derived from a linker symbol because it must already be
/// megapage-aligned, which the small `.bss` arena above (placed whereever the
/// linker fits it) doesn't guarantee.
const STACK_REGION_BASE: usize = 0x8060_0000;

/// End of `riscv_virt_board.ram` on QEMU's `virt` machine at its default size
/// (128 MiB) — just a sanity bound for [`alloc_stack_region`], not real memory
/// discovery (`STATUS.md`).
const RAM_END: usize = 0x8800_0000;

static NEXT_STACK_REGION: AtomicUsize = AtomicUsize::new(0);

/// Hands out one 2 MiB, megapage-aligned region for a thread's own stack (each
/// thread gets a distinct region, mapped only in its own page table — see
/// `paging.rs`'s module doc for why stacks need megapage, not 4 KiB, granularity
/// in this environment). Wildly oversized for an actual stack, but Phase 1 has
/// 128 MiB of RAM and two threads to fit; no reclaim, same as `alloc_frame`.
pub fn alloc_stack_region() -> usize {
    let index = NEXT_STACK_REGION.fetch_add(1, Ordering::Relaxed);
    let base = STACK_REGION_BASE + index * lantern_hal::RISCV64_MEGAPAGE_SIZE;
    assert!(base + lantern_hal::RISCV64_MEGAPAGE_SIZE <= RAM_END, "stack region arena exhausted");
    base
}
