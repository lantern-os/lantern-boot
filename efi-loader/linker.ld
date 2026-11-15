/* RFC-0032's EFI loader: linked at 0x1000 so an address here is its PE address, above the PE headers (tools/elf2efi).
 * Each part on its own page, so each segment, and so each PE section, has one set of permissions. */
OUTPUT_ARCH(riscv)
ENTRY(efi_main)

SECTIONS
{
    . = 0x1000;
    .text : { *(.text .text.*) }

    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }
    .rela.dyn : { *(.rela.dyn .rela.*) }

    . = ALIGN(4K);
    .data : { *(.data .data.* .sdata .sdata.*) }
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }
    .got : { *(.got .got.*) }
    .dynamic : { *(.dynamic) }
    .bss : { *(.bss .bss.* .sbss .sbss.*) *(COMMON) }

    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.interp) }
}
