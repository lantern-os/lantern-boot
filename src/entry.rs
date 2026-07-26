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
    // Only the boot hart proceeds — lantern-hal/lantern-kernel are single-hart
    // only (ADR-0010); park every other hart immediately rather than let it race
    // into boot_main.
    bnez a0, park

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
    // anything at all here would be worse than a plain busy-loop. Untested with
    // more than one hart (QEMU's `virt` machine defaults to a single CPU) — this
    // path has never actually run.
    j park
"#
);
