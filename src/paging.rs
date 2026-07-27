//! Builds each thread's Sv39 page table.
//!
//! **Megapage (2 MiB) granularity throughout, not 4 KiB — deliberately.** This
//! project's QEMU environment (Debian's `qemu-system-riscv64` 10.2.1) was
//! empirically confirmed, after extensive debugging, to reliably page-fault on
//! every instruction fetch following a full 3-level Sv39 walk (root -> L1 -> L0),
//! even when the resulting page table is independently verified byte-correct at
//! every level (this project's own `translate`, and raw physical-memory dumps via
//! the QEMU monitor, both confirm it). A walk with only *one* branch hop (root ->
//! L1 leaf, i.e. a megapage) was confirmed to work reliably in the same
//! environment. See [`lantern_hal::riscv64_map_megapage`]'s doc and
//! `lantern-boot/STATUS.md` for the full debugging record — this is a documented
//! environment workaround, not this project's intended long-term page size.
//!
//! **What's shared, S-mode-only (mapped identically, *without* the U bit, in
//! every thread's table):** the first megapage, `linker.ld`'s `BASE_ADDRESS`
//! through `USER_TEXT_ADDRESS` — covering the trap vector, `lantern-kernel`'s
//! dispatch, `pmm`, this module, `lantern-hal`'s own trap stack, ... — *and* the
//! boot stack `entry.rs` sets up, needed because building/entering the very first
//! thread's frame ([`lantern_kernel::enter_first_thread`]) still runs on that boot
//! stack for a few instructions *after* activating its address space (the local
//! `raw` register array `Hal::enter_thread` builds lives there) — plus the UART
//! MMIO page, for `println!`. `linker.ld`'s `ASSERT` guarantees all of that fits
//! in this one megapage.
//!
//! **What's shared, U-accessible:** the second megapage, `.user_text`
//! (`linker.ld`) — `demo.rs`'s `client_thread`/`server_thread` and their
//! `syscall`/`empty_tag` helpers, the *only* code any thread actually executes in
//! U-mode. This split exists because RISC-V never lets S-mode fetch instructions
//! from a U-accessible page (unlike loads/stores, `sstatus.SUM` doesn't override
//! this for fetches) — mapping the whole image U-accessible, as an earlier
//! revision of this file did, made *every* instruction fetch fault immediately
//! after activating a thread's table (including the trap vector's own entry,
//! since a faulting fetch's trap immediately re-faults trying to fetch the
//! handler). A real bug this session root-caused under actual QEMU hardware
//! behavior, not something any unit test could catch. See `demo.rs`'s module doc
//! for the thread-body side of this.
//!
//! **What's private:** each thread's own megapage-sized stack region (from
//! [`pmm::alloc_stack_region`]), mapped only in that thread's own table —
//! oversized for an actual stack (2 MiB for a few hundred bytes of use), the
//! price of this environment's workaround, not a real memory budget.
//!
//! **Not yet real confinement** — see `STATUS.md`: `.user_text` still shares
//! physical pages with a from-scratch user program (none exists yet — there's no
//! ELF loader) rather than being one, and there's no `.data`-is-no-execute
//! separation within it. What this *does* prove for real: genuine Sv39
//! address-space switching, genuine U-mode execution, and that the two threads'
//! stacks are actually isolated from each other (neither's table maps the
//! other's).

use lantern_hal::{riscv64_map_megapage, Riscv64PageTable, Riscv64PteFlags, RISCV64_MEGAPAGE_SIZE};

use crate::pmm;

/// Where OpenSBI loads/enters this image (`linker.ld`'s `BASE_ADDRESS`) — the
/// base of the first (kernel-only) megapage.
const KERNEL_MEGAPAGE_BASE: usize = 0x8020_0000;

/// Base of the UART's own megapage (`0x1000_0000` rounded down to a 2 MiB
/// boundary — it already sits on one).
const UART_MEGAPAGE_BASE: usize = 0x1000_0000;

unsafe extern "C" {
    /// Base of `linker.ld`'s `.user_text` megapage — see the module doc.
    static _user_text_start: u8;
}

/// Builds a fresh page table mapping the shared kernel megapage (S-mode-only) +
/// `.user_text`'s megapage (U-accessible) + UART's megapage (see the module
/// doc), plus one private megapage at `stack_base` (this thread's own stack
/// region, from [`pmm::alloc_stack_region`]).
pub fn build_table(stack_base: usize) -> usize {
    let root_paddr = pmm::alloc_frame();
    let root = root_paddr as *mut Riscv64PageTable;
    let mut alloc = pmm::alloc_frame;

    let kernel_flags = Riscv64PteFlags::READ.union(Riscv64PteFlags::WRITE).union(Riscv64PteFlags::EXECUTE);
    let user_flags = kernel_flags.union(Riscv64PteFlags::USER);
    let mmio_flags = Riscv64PteFlags::READ.union(Riscv64PteFlags::WRITE);
    let stack_flags = Riscv64PteFlags::READ.union(Riscv64PteFlags::WRITE).union(Riscv64PteFlags::USER);

    // Taking this address (never dereferencing it as an actual `u8`) doesn't
    // need `unsafe`: `&raw const` never reads through the pointer.
    let user_text_base = &raw const _user_text_start as usize;

    // SAFETY: `root` was just allocated (a fresh, zeroed, exclusively-owned
    // frame, per `pmm::alloc_frame`'s contract); `alloc` always returns a
    // distinct fresh frame for any table level `map_megapage` needs to create;
    // every address here is `RISCV64_MEGAPAGE_SIZE`-aligned (`linker.ld` places
    // `KERNEL_MEGAPAGE_BASE`/`_USER_TEXT_START` on 2 MiB boundaries, `UART_MEGAPAGE_BASE`
    // already sits on one, and `stack_base` only ever comes from
    // `pmm::alloc_stack_region`, which hands out nothing else).
    unsafe {
        riscv64_map_megapage(root, KERNEL_MEGAPAGE_BASE, KERNEL_MEGAPAGE_BASE, kernel_flags, &mut alloc);
        riscv64_map_megapage(root, user_text_base, user_text_base, user_flags, &mut alloc);
        riscv64_map_megapage(root, UART_MEGAPAGE_BASE, UART_MEGAPAGE_BASE, mmio_flags, &mut alloc);
        riscv64_map_megapage(root, stack_base, stack_base, stack_flags, &mut alloc);
    }

    debug_assert_eq!(stack_base % RISCV64_MEGAPAGE_SIZE, 0);

    root_paddr
}
