/* A genuinely standalone riscv64 ELF binary -- not linked into lantern-boot at
 * all, loaded from its own compiled bytes by lantern-boot's keystore demo
 * (src/keystore_demo/loader.rs). BASE_ADDRESS matches every other lantern-boot
 * demo program's choice -- safe to reuse verbatim, since this binary is
 * loaded into its own separate VSpace under a completely separate boot image;
 * no two demos ever run at the same time. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x84000000;

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
