//! The `riscv64` entry point. OpenSBI (QEMU's `-bios default`) jumps here in
//! S-mode with `a0 = hartid`, `a1 = pointer to the flattened device tree` — the
//! same convention the Linux/UNIX riscv64 boot protocol uses, which OpenSBI follows
//! for compatibility.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text._start
.global _start
_start:
    // Whichever hart arrives first boots, whatever its number: firmware picks the
    // boot hart, and on a real board it needn't be hart 0 (RFC-0039 §2). The flag
    // is in `.data`, not `.bss`, so clearing `.bss` can't reopen it. Every later
    // hart parks: lantern-hal/lantern-kernel are single-hart only (ADR-0010).
    la t0, lantern_boot_hart_claimed
    li t1, 1
    .option push
    .option arch, +a
    amoswap.w.aqrl t1, t1, (t0)
    .option pop
    bnez t1, park

    // Apply this image's relocations for wherever it was loaded (RFC-0039 §1,
    // `build.rs`): each R_RISCV_RELATIVE entry's word becomes its addend plus the
    // load offset. Everything up to here is PC-relative, so it runs before them.
    // Anything but R_RISCV_RELATIVE is a build this entry can't place: say so on
    // the SBI console and park.
    lla t0, _start
    lla t1, link_base
    ld t1, 0(t1)
    sub t2, t0, t1
    lla t3, __rela_dyn_start
    lla t4, __rela_dyn_end
relocate:
    bgeu t3, t4, relocated
    ld t5, 8(t3)
    li t6, 3
    bne t5, t6, bad_relocation
    ld t5, 0(t3)
    add t5, t5, t2
    ld t6, 16(t3)
    add t6, t6, t2
    sd t6, 0(t5)
    addi t3, t3, 24
    j relocate
bad_relocation:
    lla t3, bad_relocation_message
say:
    lbu a0, 0(t3)
    beqz a0, park
    li a7, 1
    ecall
    addi t3, t3, 1
    j say
relocated:
    fence.i

    // Keep `a2`/`a3`: the EFI loader's memory-map hand-off, if `a2` is its magic
    // (RFC-0039). `platform::discover` reads them.
    lla t0, lantern_boot_handoff
    sd a2, 0(t0)
    sd a3, 8(t0)

    la sp, _stack_top

    la t0, _bss_start
    la t1, _bss_end
clear_bss:
    bge t0, t1, bss_done
    sd zero, 0(t0)
    addi t0, t0, 8
    j clear_bss
bss_done:

    call boot_main

park:
    // Not `wfi` (see `demo.rs`'s idle loops for why `lantern-boot` avoids it
    // generally) — doubly so here: a parked secondary hart has no trap handler
    // installed at all (`stvec` is whatever it defaults to), so trapping into
    // anything at all here would be worse than a plain busy-loop.
    j park

.section .data
.balign 4
lantern_boot_hart_claimed:
    .word 0
.balign 8
.global lantern_boot_handoff
lantern_boot_handoff:
    .dword 0, 0

.section .rodata
.balign 8
// The link address: an absolute symbol, so the linker writes it as is and adds no relocation.
link_base:
    .dword __link_base
bad_relocation_message:
    .asciz "boot: this image has a relocation it can't apply\n"
"#
);
