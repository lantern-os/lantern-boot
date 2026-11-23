//! Boot's console ([RFC-0039](../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)).
//!
//! - **Before the device tree is read,** output goes through the firmware's SBI console: the Debug Console extension,
//!   or the legacy `console_putchar` call if the firmware lacks it. Any board with OpenSBI has one, so even "this device
//!   tree can't be used" reaches the person at the console.
//! - **After [`use_uart`],** output goes straight to the 16550-compatible UART the tree's `/chosen/stdout-path` names, at
//!   its register spacing and width, as the firmware set it up.
//!
//! This is boot-time scaffolding, not `lantern-hal`'s "early console" item. Once the shell runs, nothing in boot writes
//! here: the console is the shell's (ADR-0031).

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The UART's base, `reg_shift` and `io_width`, once [`use_uart`] has run. A base of 0 means "use SBI".
static BASE: AtomicUsize = AtomicUsize::new(0);
static SHIFT: AtomicUsize = AtomicUsize::new(0);
static WIDE: AtomicUsize = AtomicUsize::new(0);

/// Line Status Register; bit 5 is "transmit holding register empty".
const LSR: usize = 5;
const LSR_THR_EMPTY: u32 = 0x20;

/// From now on, write to the UART at `base`, registers `1 << reg_shift` bytes apart, each accessed 1 or 4 bytes wide.
///
/// # Safety
/// `base` must be a 16550-compatible UART's registers, identity-mapped (or with paging off), initialised by the
/// firmware.
pub unsafe fn use_uart(base: usize, reg_shift: u32, io_width: u32) {
    SHIFT.store(reg_shift as usize, Ordering::Relaxed);
    WIDE.store((io_width == 4) as usize, Ordering::Relaxed);
    BASE.store(base, Ordering::Release);
}

/// # Safety
/// [`use_uart`]'s registers, and never concurrently (boot is single-hart, non-reentrant: ADR-0010).
unsafe fn uart_putc(base: usize, byte: u8) {
    let shift = SHIFT.load(Ordering::Relaxed);
    let wide = WIDE.load(Ordering::Relaxed) != 0;
    let reg = |r: usize| base + (r << shift);
    // SAFETY: `use_uart`'s contract.
    unsafe {
        if wide {
            while core::ptr::read_volatile(reg(LSR) as *const u32) & LSR_THR_EMPTY == 0 {}
            core::ptr::write_volatile(reg(0) as *mut u32, byte as u32);
        } else {
            while core::ptr::read_volatile(reg(LSR) as *const u8) as u32 & LSR_THR_EMPTY == 0 {}
            core::ptr::write_volatile(reg(0) as *mut u8, byte);
        }
    }
}

/// The SBI Debug Console extension's id, "DBCN", and its write-byte function; the legacy `console_putchar` extension.
const SBI_EXT_DBCN: usize = 0x4442_434e;
const SBI_DBCN_WRITE_BYTE: usize = 2;
const SBI_LEGACY_PUTCHAR: usize = 1;

fn sbi_putc(byte: u8) {
    let error: isize;
    // SAFETY: an SBI call to M-mode firmware; it clobbers only `a0` and `a1`.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") byte as usize => error,
            lateout("a1") _,
            in("a6") SBI_DBCN_WRITE_BYTE,
            in("a7") SBI_EXT_DBCN,
            options(nostack),
        );
    }
    if error != 0 {
        // SAFETY: as above, the legacy call: `a0` is the byte, and it returns in `a0`.
        unsafe {
            core::arch::asm!(
                "ecall",
                inout("a0") byte as usize => _,
                in("a7") SBI_LEGACY_PUTCHAR,
                options(nostack),
            );
        }
    }
}

fn putc(byte: u8) {
    match BASE.load(Ordering::Acquire) {
        0 => sbi_putc(byte),
        // SAFETY: a non-zero base was set by `use_uart`, whose contract holds for boot's life; single-hart.
        base => unsafe { uart_putc(base, byte) },
    }
}

/// A `core::fmt::Write` sink over the console, so `write!`/`writeln!` work directly.
pub struct Uart;

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            putc(b);
        }
        Ok(())
    }
}

/// `println!`-style formatted output over the boot console.
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
