//! `lantern-boot` — Phase 1 prototype loader ([RFC-0004](../../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md)).
//!
//! **Scope of this first slice:** get real control from QEMU/OpenSBI, prove it with
//! UART output, and install `lantern-kernel`'s trap handler via `lantern-hal`. This
//! is deliberately *not yet* the full boot flow `lantern-boot/ARCHITECTURE.md`
//! describes — no measured boot, no kernel-image signature verification. Phase 1
//! links `lantern-kernel` directly as a library rather than loading/verifying a
//! separate signed image: RFC-0004's Phase 1 exit criterion (one confined "hello
//! service", benchmarked IPC) doesn't need that trust chain yet, and there is no
//! separate image to verify without it. See `lantern-boot/STATUS.md`.
//!
//! `riscv64` only for now (the strategic target, ADR-0002) — `x86-64` boot is a
//! separate, harder bring-up problem (real → protected → long mode) left as
//! follow-up work, matching how `lantern-hal`'s trap entries were sequenced.
#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::Write;
use core::panic::PanicInfo;

use lantern_hal::Hal;

mod demo;
mod entry;
mod uart;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let _ = writeln!(uart::Uart, "PANIC: {info}");
    loop {
        // Not `wfi`: empirically (under QEMU/OpenSBI) it crashes here rather than
        // idling, and Phase 1 has no interrupt/timer handling to wake into safely
        // regardless (`lantern-hal/STATUS.md`) — see `demo.rs`'s identical choice
        // for the full explanation.
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot -- Phase 1 prototype");
    println!("hartid={hartid} dtb={dtb:#x}");

    // SAFETY: called exactly once, here, before any trap can occur — the required
    // precondition on `install_trap_handler`.
    unsafe {
        lantern_hal::Hardware::install_trap_handler(lantern_kernel::kernel_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the trap
    // handler and before anything else could trap.
    unsafe { demo::run() }
}
