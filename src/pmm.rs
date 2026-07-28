//! Where this crate's real physical memory lives, as far as `loader.rs` needs to
//! know it.
//!
//! **Phase 1 stand-in for real physical memory discovery.** Real discovery from
//! the device tree `boot_main` already receives is still deferred
//! (`STATUS.md`) — these are hardcoded facts about QEMU's `riscv64` `virt`
//! machine at its default RAM size, the same kind of hardcoded-machine-fact
//! this crate already relies on elsewhere (`uart.rs`'s fixed UART0 address,
//! `linker.ld`'s kernel/`.user_text` megapage placement).
//!
//! [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md)
//! moved real physical-memory bookkeeping *into* `lantern-kernel` itself
//! (`Untyped::bump`, backed by the range below) — this module no longer hands out
//! frames directly the way an earlier revision did; `loader.rs` seeds one
//! memory-backed `Untyped` from [`GENERAL_MEMORY_BASE`]/[`GENERAL_MEMORY_END`] at
//! boot, and every VSpace/Frame (including page-table-internal frames
//! `FrameInvoke::Map` allocates on demand) comes from retyping that, not a
//! separate boot-only allocator.

/// Where `linker.ld` ends the two megapages it reserves for the kernel image and
/// `.user_text` (`0x8020_0000` + 2x [`lantern_hal::RISCV64_MEGAPAGE_SIZE`]) —
/// hardcoded rather than derived from a linker symbol because
/// `Untyped::with_memory`'s range must already be megapage-aligned, which a
/// linker-placed symbol doesn't guarantee.
pub const GENERAL_MEMORY_BASE: usize = 0x8060_0000;

/// End of `riscv_virt_board.ram` on QEMU's `virt` machine at its default size
/// (128 MiB).
pub const GENERAL_MEMORY_END: usize = 0x8800_0000;
