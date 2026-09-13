//! `lantern-boot-keystore-demo` — a **fourth, isolated binary** in this
//! crate, proving a real, confined
//! [`lantern_crypto::Keystore`] running as an
//! [RFC-0018](../../../lantern-rfcs/rfcs/0018-confined-execution-port.md)/
//! [ADR-0022](../../../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)
//! confined service under QEMU: a live capability grant over real IPC, then
//! real SIGN/ENCRYPT/DECRYPT dispatch
//! ([RFC-0019](../../../lantern-rfcs/rfcs/0019-confined-service-call-protocol.md)/
//! [ADR-0024](../../../lantern-rfcs/adr/0024-confined-service-call-protocol.md))
//! over a real shared `Frame`. See `../broker_demo/main.rs`'s module doc for
//! why this is a wholly separate binary rather than a program merged into an
//! existing demo.
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
/// `../frame_demo/main.rs`'s trap handler — including its `Signal`
/// SUCCESS/FAILURE narration convention (see that module's doc for why
/// `incoming_mr0`, captured before dispatch, is what distinguishes them).
/// `CNodeInvoke` additionally narrates here (the live `Broker::mint`) since
/// this demo, unlike `frame_demo`, exercises a real grant round, not just a
/// pre-wired shared endpoint.
#[cfg(target_arch = "riscv64")]
fn keystore_demo_trap_handler(frame: &mut TrapFrame) {
    let syscall = SyscallNumber::from_usize(frame.syscall_number());
    let incoming_mr0 = frame.mr(0);

    lantern_kernel::kernel_trap_handler(frame);

    match syscall {
        Some(SyscallNumber::Call) => println!("keystore-demo: client Call'd the keystore-service"),
        Some(SyscallNumber::Recv) => {
            println!("keystore-demo: keystore-service Recv'd -- ok={}", !frame.tag().is_error())
        }
        Some(SyscallNumber::CNodeInvoke) => println!(
            "keystore-demo: keystore-service Mint'd an attenuated, badged copy of its endpoint -- ok={}",
            !frame.tag().is_error()
        ),
        Some(SyscallNumber::Reply) => {
            println!("keystore-demo: keystore-service Reply'd -- ok={}", !frame.tag().is_error())
        }
        Some(SyscallNumber::Signal) => {
            let which = match incoming_mr0 {
                cptr if cptr == loader::CLIENT_SUCCESS_CPTR => "SUCCESS",
                cptr if cptr == loader::CLIENT_FAILURE_CPTR => "FAILURE",
                _ => "unknown",
            };
            println!(
                "keystore-demo: client Signal'd {which} -- ok={} (the real proof: ENCRYPT then DECRYPT through the confined keystore-service round-tripped back to the original plaintext)",
                !frame.tag().is_error()
            );
        }
        _ => {}
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
extern "C" fn boot_main(hartid: usize, dtb: usize) -> ! {
    println!();
    println!("LanternOS lantern-boot-keystore-demo -- confined Keystore over RFC-0019/ADR-0024");
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
        lantern_hal::Hardware::install_trap_handler(keystore_demo_trap_handler);
    }
    println!("trap handler installed");

    // SAFETY: called exactly once, here, immediately after installing the
    // trap handler and before anything else could trap.
    unsafe { loader::run(mem_end) }
}
