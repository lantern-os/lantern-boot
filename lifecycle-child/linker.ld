/* RFC-0030's child, built by the nursery (../nursery/) from 4 KiB Frames, not by lantern-boot's loader. Every section
 * starts on its own page, so each page has one segment's permissions: the text is never writable, which kind 3's store
 * relies on. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x84000000;

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
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
