/* riscv64 QEMU 'virt' machine, `-bios default` (OpenSBI): OpenSBI itself loads at
 * 0x80000000 and jumps to the "payload" kernel at 0x80200000 in S-mode, per the
 * standard convention essentially every bare-metal riscv64-under-QEMU project
 * relies on. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

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

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
