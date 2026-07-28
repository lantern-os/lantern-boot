/* A genuinely standalone riscv64 ELF binary -- not linked into lantern-boot at
 * all, loaded from its own compiled bytes by lantern-boot's ELF loader
 * (RFC-0008/ADR-0012). BASE_ADDRESS is arbitrary but fixed, chosen well clear
 * of lantern-boot's own kernel/.user_text megapages (0x8020_0000..0x8060_0000)
 * and the megapage-sized per-thread stack regions lantern-boot/pmm.rs hands out
 * starting at 0x8060_0000 -- comfortable headroom (dozens of MB) before this
 * address for any realistic number of Phase 1 demo threads. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x84000000;

/* Phase 1's loader retypes one Frame (2 MiB, megapage-granularity --
 * lantern-hal/STATUS.md's QEMU workaround) per PT_LOAD segment, requiring each
 * segment's own p_vaddr to already be megapage-aligned (the loader does not
 * currently handle a segment straddling, or sharing a megapage with, another
 * segment -- see lantern-boot/elf.rs). Forcing .data onto a fresh megapage
 * boundary here, rather than leaving it wherever the linker's default
 * RX/RW segment split would put it, is what guarantees that. */
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

    . = BASE_ADDRESS + MEGAPAGE_SIZE;

    .data : {
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
