//! `lantern-boot-runtime-fs-demo` — an **eighth, isolated binary**, and the
//! [RFC-0018](../../../lantern-rfcs/rfcs/0018-confined-execution-port.md)
//! filesystem integration proof: a confined `lantern-runtime` process hosting
//! a real Wasm guest component whose `lantern:host/filesystem` grant is served
//! over a real shared `Frame` by a confined `store-service`, which seals every
//! block through a confined `keystore-service`. See `loader.rs`'s module doc for the topology and
//! `../broker_demo/main.rs`'s for why this is its own binary.
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

/// Narrates the demo's syscalls from S-mode, same style as
/// `../runtime_demo/main.rs`'s trap handler. `Signal` additionally prints the
/// runtime's stage code and detail word — `a1`/`a2`, captured before dispatch,
/// which `Signal` itself ignores (`confined-runtime/src/main.rs`'s
/// "Diagnostics"): stage `0` with the runtime's heap bytes used on
/// success, the failing step otherwise.
#[cfg(target_arch = "riscv64")]
fn runtime_fs_demo_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());
    let incoming = [frame.mr(0), frame.mr(1), frame.mr(2)];

    lantern_kernel::kernel_trap_handler(frame);

    let ok = !frame.tag().is_error();
    match syscall {
        Some(SyscallNumber::Call) => println!("runtime-fs-demo: Call -- ok={ok}"),
        Some(SyscallNumber::CNodeInvoke) => {
            println!("runtime-fs-demo: a service Mint'd an attenuated, badged copy of its endpoint -- ok={ok}")
        }
        Some(SyscallNumber::FrameInvoke) => {
            println!("runtime-fs-demo: runtime FrameInvoke'd an arena Frame (Wasmtime mmap/munmap) -- ok={ok}")
        }
        Some(SyscallNumber::Signal) => {
            let which = match incoming[0] {
                cptr if cptr == loader::RUNTIME_SUCCESS_CPTR => "SUCCESS",
                cptr if cptr == loader::RUNTIME_FAILURE_CPTR => "FAILURE",
                _ => "unknown",
            };
            println!("runtime-fs-demo: runtime Signal'd {which} -- ok={ok} stage={} detail={}", incoming[1], incoming[2]);
            if which == "SUCCESS" {
                println!(
                    "runtime-fs-demo: the real proof: a confined Wasm guest wrote and read back a file served by a confined store-service, sealed through a confined keystore-service; an oversized write was refused without changing it, and an ungranted slot read back none"
                );
            }
        }
        _ => {}
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot-runtime-fs-demo -- a confined Wasm guest over IpcFilesystem (RFC-0018)");
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
        lantern_hal::Hardware::install_trap_handler(runtime_fs_demo_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the
    // trap handler and before anything else could trap.
    unsafe { loader::run(mem_end) }
}
