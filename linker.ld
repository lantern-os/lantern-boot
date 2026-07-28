/* riscv64 QEMU 'virt' machine, `-bios default` (OpenSBI): OpenSBI itself loads at
 * 0x80000000 and jumps to the "payload" kernel at 0x80200000 in S-mode, per the
 * standard convention essentially every bare-metal riscv64-under-QEMU project
 * relies on. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

/* Sv39 megapage size (2 MiB) — `loader.rs` maps this whole image at that
 * granularity (one megapage, S-mode-only — every loaded program's VSpace needs
 * it mapped for the trap vector/kernel dispatch/`sret` cold-start path to keep
 * working after that program's own table is active, RISC-V traps don't switch
 * page tables), a documented workaround for a QEMU environment limitation with
 * full 3-level (4 KiB) walks — see `lantern-hal`'s `riscv64_paging::map_megapage`
 * doc and `lantern-boot/STATUS.md` for the full story. Loaded programs' own code
 * lives in their own retyped Frames (RFC-0008/ADR-0012), not in this image at
 * all — there is no `.user_text`-equivalent section here any more. */
MEGAPAGE_SIZE = 0x200000;

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

    ASSERT(_stack_top <= BASE_ADDRESS + MEGAPAGE_SIZE,
           "kernel image (.text through the boot stack) overflowed past its one reserved 2 MiB megapage")

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
