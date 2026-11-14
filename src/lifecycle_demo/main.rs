//! `lantern-boot-lifecycle-demo` — [RFC-0030](../../../lantern-rfcs/rfcs/0030-process-lifecycle-faults-and-reclamation.md)'s
//! proof that processes can be built, can fault, and can be reclaimed from user space, without stopping the system. See
//! `loader.rs`, and `scripts/lifecycle-demo.sh`.
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
fn lifecycle_demo_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());
    let incoming = [frame.mr(0), frame.mr(1), frame.mr(2)];
    lantern_kernel::kernel_trap_handler(frame);
    if let Some(SyscallNumber::Signal) = syscall {
        let which = match incoming[0] {
            cptr if cptr == loader::DONE_CPTR => "SUCCESS",
            cptr if cptr == loader::FAILURE_CPTR => "FAILURE",
            _ => return,
        };
        println!("lifecycle-demo: nursery Signal'd {which} -- ok={} a={} b={}", !frame.tag().is_error(), incoming[1], incoming[2]);
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot-lifecycle-demo -- processes built, lost and reclaimed from user space (RFC-0030)");
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
        lantern_hal::Hardware::install_trap_handler(lifecycle_demo_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the
    // trap handler and before anything else could trap.
    unsafe { loader::run(mem_end) }
}
