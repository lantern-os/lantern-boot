//! `lantern-boot-wasm-probe-demo` — a **sixth, isolated binary**, proving
//! `lantern-runtime/riscv64-probe`'s Wasmtime `no_std` + Pulley `riscv64` link
//! proof ([RFC-0018](../../../lantern-rfcs/rfcs/0018-confined-execution-port.md)
//! Part 3 / [ADR-0023](../../../lantern-rfcs/adr/0023-wasmtime-no-std-pulley-hosting.md))
//! actually **runs** under the real kernel and loader, not just `cargo test`'s
//! host-side platform-shim exercise. See `src/wasm_probe_demo/loader.rs`'s
//! module doc for what this does and doesn't prove, and
//! `../broker_demo/main.rs`'s module doc for why this is a wholly separate
//! binary rather than a program merged into an existing demo.
//!
//! Simplest trap handler of any demo in this crate: the probe does no IPC at
//! all (it's a single, self-contained program), so `Signal` is the only
//! syscall this demo ever narrates.
//!
//! Shares the genuinely portable pieces of this crate (`elf.rs`, `pmm.rs`,
//! `uart.rs`, `entry.rs`, `launch.rs`) with `../main.rs` via `#[path]`,
//! compiled fresh into this binary's own separate crate root.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[path = "../elf.rs"]
mod elf;

#[path = "../fdt.rs"]
mod fdt;
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
#[path = "../launch.rs"]
mod launch;
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

/// Narrates the demo's one syscall from S-mode, same `Signal` convention
/// every other demo's trap handler uses.
#[cfg(target_arch = "riscv64")]
fn wasm_probe_demo_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());
    let incoming_mr0 = frame.mr(0);

    lantern_kernel::kernel_trap_handler(frame);

    if let Some(SyscallNumber::Signal) = syscall {
        let which = match incoming_mr0 {
            cptr if cptr == loader::PROBE_SUCCESS_CPTR => "SUCCESS",
            cptr if cptr == loader::PROBE_FAILURE_CPTR => "FAILURE",
            _ => "unknown",
        };
        println!(
            "wasm-probe-demo: probe Signal'd {which} -- ok={} (the real proof: a Wasmtime+Pulley component ran under the real kernel and computed the expected answer)",
            !frame.tag().is_error()
        );
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot-wasm-probe-demo -- Wasmtime+Pulley under the real kernel");
    println!("hartid={hartid} dtb={dtb:#x}");

    // SAFETY: `dtb` is the FDT pointer OpenSBI passed in `a1`.
    let mem_end = match unsafe { fdt::ram_region(dtb as *const u8) } {
        Some((base, size)) => {
            let end = base.saturating_add(size) as usize;
            println!("boot: DTB reports RAM {base:#x}..{end:#x}");
            end
        }
        None => {
            println!("boot: DTB unreadable, using the hardcoded RAM end {:#x}", pmm::GENERAL_MEMORY_END);
            pmm::GENERAL_MEMORY_END
        }
    };

    // SAFETY: called exactly once, here, before any trap can occur.
    unsafe {
        lantern_hal::Hardware::install_trap_handler(wasm_probe_demo_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the
    // trap handler and before anything else could trap.
    unsafe { loader::run(mem_end) }
}
