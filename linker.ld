/* riscv64 QEMU 'virt' machine, `-bios default` (OpenSBI): OpenSBI itself loads at
 * 0x80000000 and jumps to the "payload" kernel at 0x80200000 in S-mode, per the
 * standard convention essentially every bare-metal riscv64-under-QEMU project
 * relies on. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

/* Sv39 megapage size (2 MiB) — `paging.rs` maps this image at that granularity
 * exclusively, a documented workaround for a QEMU environment limitation with
 * full 3-level (4 KiB) walks; see `.user_text`'s comment and
 * `lantern-hal`'s `riscv64_paging::map_megapage` doc for the full story. */
MEGAPAGE_SIZE = 0x200000;

/* Every *other* section (.text/.rodata/.data/.bss/the boot stack) must fit in
 * the first megapage, [BASE_ADDRESS, USER_TEXT_ADDRESS) — `paging.rs` maps
 * that whole window as one kernel-only (non-U) megapage. */
USER_TEXT_ADDRESS = BASE_ADDRESS + MEGAPAGE_SIZE;

SECTIONS
{
    . = BASE_ADDRESS;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        PROVIDE(_bss_start = .);
        *(.bss .bss.*)
        *(COMMON)
        PROVIDE(_bss_end = .);
    }

    . = ALIGN(4K);
    PROVIDE(_stack_bottom = .);
    . += 64K; /* Phase 1: one hart, one boot-time stack — not sized for anything else. */
    PROVIDE(_stack_top = .);

    ASSERT(_stack_top <= USER_TEXT_ADDRESS,
           "kernel image (.text through the boot stack) overflowed past the first 2 MiB megapage into .user_text's reserved window")

    /* Code the demo threads actually execute in real U-mode (`lantern-boot`'s
     * `demo.rs`) — placed at a fixed 2 MiB-aligned address and reserving the
     * *whole* following megapage (regardless of this section's actual, much
     * smaller, size) so `paging.rs` can map exactly that one megapage U-accessible
     * and nothing else. Everything above (the trap vector, `lantern-kernel`'s
     * dispatch, `activate_address_space`'s `csrw satp`/`sfence.vma`/`sret`
     * cold-start path, ...) still executes in S-mode even after a thread's page
     * table is active, and RISC-V forbids S-mode from ever fetching instructions
     * from a U-accessible page (unlike loads/stores, `sstatus.SUM` does not
     * override this for fetches) — see `paging.rs`'s module doc for the full
     * story. */
    . = USER_TEXT_ADDRESS;
    .user_text : {
        PROVIDE(_user_text_start = .);
        *(.user_text .user_text.*)
    }
    . = USER_TEXT_ADDRESS + MEGAPAGE_SIZE;
    PROVIDE(_user_text_end = .);

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
