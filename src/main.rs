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
//!
//! `#![no_std]`/`#![no_main]` are conditional on `not(test)`, and every
//! `riscv64`-only module/item below is gated on `target_arch = "riscv64"`
//! (raw `ecall`/MMIO/linker-section code that simply cannot build for any other
//! target) — the same pattern `lantern-hal`/`lantern-kernel` already use, applied
//! here so [`elf`] (portable, hand-written ELF64 parsing — RFC-0008/ADR-0012) has
//! real host-test coverage via `cargo test --target <host triple>` (this crate's
//! own `.cargo/config.toml` still defaults *builds* to `riscv64gc-unknown-none-elf`,
//! so the real boot binary is unaffected).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

mod elf;

#[cfg(target_arch = "riscv64")]
mod entry;
#[cfg(target_arch = "riscv64")]
mod loader;
#[cfg(target_arch = "riscv64")]
mod pmm;
#[cfg(target_arch = "riscv64")]
mod uart;

#[cfg(target_arch = "riscv64")]
use core::fmt::Write;
#[cfg(target_arch = "riscv64")]
use core::panic::PanicInfo;

#[cfg(target_arch = "riscv64")]
use lantern_hal::{Hal, TrapFrame};
#[cfg(target_arch = "riscv64")]
use lantern_kernel::syscall::SyscallNumber;

#[cfg(target_arch = "riscv64")]
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

/// Wraps [`lantern_kernel::kernel_trap_handler`] to narrate the demo's syscalls
/// on the console. Entirely S-mode code (every trap runs in S-mode, regardless
/// of which privilege the interrupted thread was in) — unlike the thread bodies
/// in `demo.rs`, it's free to use `println!`; see `demo.rs`'s module doc for why
/// they can't. Prints the *incoming* request before dispatch (dispatch may
/// switch `frame` to a different, newly-resumed thread's context) and the
/// *outgoing* result after.
#[cfg(target_arch = "riscv64")]
fn boot_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());
    let incoming_mr1 = frame.mr(1);

    lantern_kernel::kernel_trap_handler(frame);

    match syscall {
        Some(SyscallNumber::Call) => {
            println!("boot: client Call'd with payload {incoming_mr1}")
        }
        Some(SyscallNumber::Recv) => {
            println!("boot: a Recv rendezvoused; receiver now has payload {}", frame.mr(1))
        }
        Some(SyscallNumber::Reply) => println!(
            "boot: server Reply'd {incoming_mr1}; caller now resumed with reply {}",
            frame.mr(1)
        ),
        _ => {}
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot -- Phase 1 prototype");
    println!("hartid={hartid} dtb={dtb:#x}");

    // SAFETY: called exactly once, here, before any trap can occur — the required
    // precondition on `install_trap_handler`.
    unsafe {
        lantern_hal::Hardware::install_trap_handler(boot_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the trap
    // handler and before anything else could trap.
    unsafe { loader::run() }
}
