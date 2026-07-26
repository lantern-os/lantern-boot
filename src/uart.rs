//! A raw, boot-internal ns16550a UART driver for QEMU's `riscv64` `virt` machine
//! (UART0 fixed at `0x1000_0000`).
//!
//! **This is not `lantern-hal`'s "early console" HAL item** (`lantern-hal/STATUS.md`
//! lists that as not yet started). It's boot-time bring-up scaffolding, hardcoded to
//! one specific QEMU MMIO address, kept deliberately separate from and not claiming
//! to satisfy the portable HAL abstraction that item describes.

use core::fmt;

const UART0_BASE: usize = 0x1000_0000;
/// Line Status Register offset; bit 5 (`0x20`) is "transmit holding register empty".
const LSR_OFFSET: usize = 5;
const LSR_THR_EMPTY: u8 = 0x20;

/// # Safety
/// Must only be called after the UART is known to be mapped and initialised by the
/// platform (true unconditionally on QEMU's `virt` machine — there is no separate
/// UART init step to do), and never concurrently (Phase 1 is single-hart,
/// non-reentrant — ADR-0010).
unsafe fn putc(byte: u8) {
    let base = UART0_BASE as *mut u8;
    // SAFETY: `UART0_BASE` is QEMU virt's fixed, always-mapped UART0 MMIO address;
    // caller upholds the rest of this function's contract.
    unsafe {
        while core::ptr::read_volatile(base.add(LSR_OFFSET)) & LSR_THR_EMPTY == 0 {}
        core::ptr::write_volatile(base, byte);
    }
}

/// A `core::fmt::Write` sink over the raw UART, so `write!`/`writeln!` work directly.
pub struct Uart;

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            // SAFETY: see `putc`'s contract — upheld by this crate being single-hart
            // and calling this only after entry, never from a trap/interrupt context.
            unsafe { putc(b) };
        }
        Ok(())
    }
}

/// `println!`-style formatted output over the boot UART.
#[macro_export]
macro_rules! println {
    () => {{
        use core::fmt::Write;
        let _ = writeln!($crate::uart::Uart);
    }};
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::uart::Uart, $($arg)*);
    }};
}
