//! `lantern-uart-driver` — [RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md)'s proof
//! that a confined program can drive a device from its interrupts.
//!
//! It holds the UART's 4 KiB device Frame (mapped at [`UART_VADDR`]), an `IrqHandler` for the UART's line, a
//! notification, and two notifications to report on. It never runs in S-mode, and nothing else here can reach
//! another device's registers or line.
//!
//! It binds its line, enables the UART's receive interrupt, and then loops: wait for the notification, read and echo
//! every byte the UART holds, and acknowledge. At the first newline it signals `DONE` with the number of bytes read
//! and their sum, which the demo's script checks against what it typed.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::sys::{self, irq};

const IRQ_CPTR: usize = 1;
const NOTIFICATION_CPTR: usize = 2;
const DONE_CPTR: usize = 3;
const FAILURE_CPTR: usize = 4;

/// Must equal `irq_demo/loader.rs`'s `UART_VADDR`. Not the UART's physical address: the kernel's own S-mode mapping
/// of the UART's megapage is at that address in every VSpace.
const UART_VADDR: usize = 0x9500_0000;

/// ns16550a registers, a byte each.
const RBR_THR: usize = 0;
const IER: usize = 1;
const LSR: usize = 5;
const IER_RX_AVAILABLE: u8 = 1 << 0;
const LSR_DATA_READY: u8 = 1 << 0;
const LSR_THR_EMPTY: u8 = 1 << 5;

lantern_abi::entry!(run);

fn register(offset: usize) -> *mut u8 {
    (UART_VADDR + offset) as *mut u8
}

fn read(offset: usize) -> u8 {
    // SAFETY: the loader mapped the UART's 4 KiB page read/write at UART_VADDR for this program's whole life, and
    // these are its byte registers.
    unsafe { core::ptr::read_volatile(register(offset)) }
}

fn write(offset: usize, value: u8) {
    // SAFETY: as `read`.
    unsafe { core::ptr::write_volatile(register(offset), value) }
}

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);
    if irq::set_notification(IRQ_CPTR, NOTIFICATION_CPTR).is_err() {
        fail(1);
    }
    write(IER, IER_RX_AVAILABLE);

    let (mut count, mut sum) = (0usize, 0usize);
    loop {
        if sys::wait(NOTIFICATION_CPTR).is_err() {
            fail(2);
        }
        let mut done = false;
        while read(LSR) & LSR_DATA_READY != 0 {
            let byte = read(RBR_THR);
            while read(LSR) & LSR_THR_EMPTY == 0 {}
            write(RBR_THR, byte);
            count += 1;
            sum += byte as usize;
            done |= byte == b'\n' || byte == b'\r';
        }
        if irq::ack(IRQ_CPTR).is_err() {
            fail(3);
        }
        if done {
            let _ = sys::signal_with(DONE_CPTR, count, sum);
            park();
        }
    }
}

fn fail(step: usize) -> ! {
    let _ = sys::signal_with(FAILURE_CPTR, step, 0);
    park()
}

/// Waits on a notification nothing signals again, without spinning.
fn park() -> ! {
    loop {
        let _ = sys::wait(DONE_CPTR);
    }
}
