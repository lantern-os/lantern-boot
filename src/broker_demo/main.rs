//! `lantern-boot-broker-demo` — a **second, isolated binary** in this crate,
//! proving [RFC-0010](../../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)'s
//! capability-brokering mechanism runs for real, under confined U-mode
//! `ecall`s, not just against a direct `KernelState`
//! ([`lantern_capabilities::Broker`](../../../lantern-capabilities/src/lib.rs)'s
//! own validation). See `../broker_demo/loader.rs`'s module doc for why this
//! is a wholly separate binary rather than a third program merged into
//! `../main.rs`'s existing, already-QEMU-validated two-thread IPC benchmark.
//!
//! Shares the genuinely portable pieces of this crate (`elf.rs`, `pmm.rs`,
//! `uart.rs`, `entry.rs`) with `../main.rs` via `#[path]`, compiled fresh
//! into this binary's own separate crate root — no code is duplicated by
//! hand, but nothing here can accidentally affect `../main.rs`'s own build
//! either. `loader.rs` (this module's sibling) is this binary's own,
//! unshared, since its actual demo logic is entirely different.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[path = "../elf.rs"]
mod elf;
#[cfg(target_arch = "riscv64")]
#[path = "../entry.rs"]
mod entry;
#[cfg(target_arch = "riscv64")]
#[path = "../pmm.rs"]
mod pmm;
#[cfg(target_arch = "riscv64")]
#[path = "../uart.rs"]
mod uart;
#[cfg(target_arch = "riscv64")]
mod loader;

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
        core::hint::spin_loop();
    }
}

/// Narrates each syscall in this demo's confined broker/client exchange
/// directly from its own real dispatch result — not self-reported by either
/// program (`../../broker-service/`, `../../broker-client/` don't even
/// check their own return values, see either's module doc). `Call` is the
/// one exception: it genuinely blocks the caller and hands control to
/// whichever thread the kernel switches to, so `frame` no longer reflects
/// the *caller's* own state by the time dispatch returns — narrated as a
/// bare event, not an outcome. Every other syscall here either never blocks
/// (`Recv`'s immediate-rendezvous path, `CNodeInvoke`, `Signal`) or, for
/// `Reply`, resumes a thread whose own tag is only ever non-error on success
/// (a normal resume) — so `frame.tag().is_error()` post-dispatch is a
/// faithful read of what actually happened.
///
/// This design also sidesteps a real, reproducible anomaly found while
/// building this demo: `broker-service` never resumes after its own `Reply`
/// (confirmed via diagnostic instrumentation during development — see
/// `STATUS.md`), evidently a new trigger for the project's existing,
/// documented, unresolved IPC round-trip-loss bug
/// (`lantern-kernel/STATUS.md`'s "Known Phase 1 gaps"). Narrating from the
/// dispatch side, rather than depending on either program reporting its own
/// outcome after the fact, needs neither program to resume again once its
/// part in the exchange is done.
#[cfg(target_arch = "riscv64")]
fn broker_demo_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());

    lantern_kernel::kernel_trap_handler(frame);

    match syscall {
        Some(SyscallNumber::Call) => println!("broker-demo: client Call'd the broker, registering its reply destination"),
        Some(SyscallNumber::Recv) => {
            println!("broker-demo: broker Recv'd the client's request -- ok={}", !frame.tag().is_error())
        }
        Some(SyscallNumber::CNodeInvoke) => println!(
            "broker-demo: broker Mint'd an attenuated, badged copy of its resource -- ok={}",
            !frame.tag().is_error()
        ),
        Some(SyscallNumber::Reply) => println!(
            "broker-demo: broker Reply'd with the capability attached (extra_caps == 1) -- ok={}",
            !frame.tag().is_error()
        ),
        Some(SyscallNumber::Signal) => println!(
            "broker-demo: client Signal'd the granted capability -- ok={} (the real proof: only a genuinely transferred, WRITE-rights capability can succeed here)",
            !frame.tag().is_error()
        ),
        _ => {}
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot-broker-demo -- RFC-0010 confined broker demo");
    println!("hartid={hartid} dtb={dtb:#x}");

    // SAFETY: called exactly once, here, before any trap can occur.
    unsafe {
        lantern_hal::Hardware::install_trap_handler(broker_demo_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the
    // trap handler and before anything else could trap.
    unsafe { loader::run() }
}
