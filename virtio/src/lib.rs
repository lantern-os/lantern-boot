//! virtio 1.x over MMIO (version 2), for `net-driver` and `rng-driver`
//! ([RFC-0035](../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)): the registers, the device handshake (virtio
//! 1.1 §3.1.1), and split virtqueues laid out in one 4 KiB DMA page each.
//!
//! A driver is trusted with memory until there's an IOMMU: the device reaches whatever physical address a descriptor
//! names. Every address written here is one of the driver's own DMA pages, which only a DMA `Untyped` reveals.

#![no_std]

use core::sync::atomic::{fence, Ordering};

pub const MAGIC: usize = 0x000;
pub const VERSION: usize = 0x004;
pub const DEVICE_ID: usize = 0x008;
pub const DEVICE_FEATURES: usize = 0x010;
pub const DEVICE_FEATURES_SEL: usize = 0x014;
pub const DRIVER_FEATURES: usize = 0x020;
pub const DRIVER_FEATURES_SEL: usize = 0x024;
pub const QUEUE_SEL: usize = 0x030;
pub const QUEUE_NUM_MAX: usize = 0x034;
pub const QUEUE_NUM: usize = 0x038;
pub const QUEUE_READY: usize = 0x044;
pub const QUEUE_NOTIFY: usize = 0x050;
pub const INTERRUPT_STATUS: usize = 0x060;
pub const INTERRUPT_ACK: usize = 0x064;
pub const STATUS: usize = 0x070;
pub const QUEUE_DESC: usize = 0x080;
pub const QUEUE_DRIVER: usize = 0x090;
pub const QUEUE_DEVICE: usize = 0x0a0;
pub const CONFIG: usize = 0x100;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
/// `VIRTIO_F_VERSION_1`, bit 32: word 1, bit 0.
const F_VERSION_1: u32 = 1 << 0;

pub const DESC_NEXT: u16 = 1;
pub const DESC_WRITE: u16 = 2;
pub const QUEUE_SIZE: u16 = 8;
/// A queue's page: descriptors, then the driver ring, then the device ring.
const DESC: usize = 0;
const AVAIL: usize = 128;
const USED: usize = 256;

/// One device's registers, at the address its page is mapped.
#[derive(Clone, Copy)]
pub struct Regs(pub usize);

impl Regs {
    pub fn read(self, offset: usize) -> u32 {
        // SAFETY: the loader mapped the device's 4 KiB register page read/write at `self.0` for the driver's whole life,
        // and these are its 32-bit registers.
        unsafe { core::ptr::read_volatile((self.0 + offset) as *const u32) }
    }

    pub fn write(self, offset: usize, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile((self.0 + offset) as *mut u32, value) }
    }

    pub fn config_byte(self, at: usize) -> u8 {
        // SAFETY: as `read`; the device's configuration is byte-addressable.
        unsafe { core::ptr::read_volatile((self.0 + CONFIG + at) as *const u8) }
    }

    /// Acknowledges the device's pending interrupt.
    pub fn ack(self) {
        self.write(INTERRUPT_ACK, self.read(INTERRUPT_STATUS));
    }
}

/// Orders every memory and device access before it against every one after: the device reads the queues by DMA.
pub fn barrier() {
    fence(Ordering::SeqCst);
    // SAFETY: a fence has no operands and no effect beyond ordering.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack))
    };
}

/// Why bringing a device up failed: the step, for the driver's failure report.
pub type Step = usize;

/// The handshake up to `FEATURES_OK` for a device of `device_id`, accepting `VERSION_1` and the low-word `features` the
/// device offers among those asked for. Returns the low-word features agreed.
pub fn begin(regs: Regs, device_id: u32, features: u32) -> Result<u32, Step> {
    if regs.read(MAGIC) != 0x7472_6976 || regs.read(VERSION) != 2 || regs.read(DEVICE_ID) != device_id {
        return Err(1);
    }
    regs.write(STATUS, 0);
    regs.write(STATUS, STATUS_ACKNOWLEDGE);
    regs.write(STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    regs.write(DEVICE_FEATURES_SEL, 1);
    if regs.read(DEVICE_FEATURES) & F_VERSION_1 == 0 {
        return Err(5);
    }
    regs.write(DEVICE_FEATURES_SEL, 0);
    let agreed = regs.read(DEVICE_FEATURES) & features;
    regs.write(DRIVER_FEATURES_SEL, 0);
    regs.write(DRIVER_FEATURES, agreed);
    regs.write(DRIVER_FEATURES_SEL, 1);
    regs.write(DRIVER_FEATURES, F_VERSION_1);
    regs.write(STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if regs.read(STATUS) & STATUS_FEATURES_OK == 0 {
        return Err(6);
    }
    Ok(agreed)
}

/// Sets `DRIVER_OK`: the device may start.
pub fn finish(regs: Regs) {
    regs.write(STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
}

/// A split virtqueue in one DMA page, mapped at `vaddr`, physically at `paddr`.
pub struct Queue {
    pub index: u16,
    vaddr: usize,
    paddr: u64,
    next_avail: u16,
    last_used: u16,
}

impl Queue {
    /// Sets queue `index` up in its page. The page must be zeroed, as a freshly retyped Frame is.
    pub fn new(regs: Regs, index: u16, vaddr: usize, paddr: u64) -> Result<Self, Step> {
        regs.write(QUEUE_SEL, index as u32);
        if regs.read(QUEUE_READY) != 0 || regs.read(QUEUE_NUM_MAX) < QUEUE_SIZE as u32 {
            return Err(7);
        }
        regs.write(QUEUE_NUM, QUEUE_SIZE as u32);
        for (reg, offset) in [(QUEUE_DESC, DESC), (QUEUE_DRIVER, AVAIL), (QUEUE_DEVICE, USED)] {
            let a = paddr + offset as u64;
            regs.write(reg, a as u32);
            regs.write(reg + 4, (a >> 32) as u32);
        }
        regs.write(QUEUE_READY, 1);
        Ok(Self { index, vaddr, paddr, next_avail: 0, last_used: 0 })
    }

    fn put<T: Copy>(&self, at: usize, value: T) {
        // SAFETY: `at` is inside the queue's page, mapped read/write at `vaddr`, and aligned for `T` by the layout above.
        // The device reads it by DMA, so it's written volatile.
        unsafe { core::ptr::write_volatile((self.vaddr + at) as *mut T, value) }
    }

    fn get<T: Copy>(&self, at: usize) -> T {
        // SAFETY: as `put`.
        unsafe { core::ptr::read_volatile((self.vaddr + at) as *const T) }
    }

    /// Fills in descriptor `i`.
    pub fn descriptor(&self, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let at = DESC + i as usize * 16;
        self.put(at, addr);
        self.put(at + 8, len);
        self.put(at + 12, flags);
        self.put(at + 14, next);
    }

    /// Offers the chain starting at descriptor `head` to the device, and tells it.
    pub fn offer(&mut self, regs: Regs, head: u16) {
        self.put(AVAIL + 4 + (self.next_avail % QUEUE_SIZE) as usize * 2, head);
        barrier();
        self.next_avail = self.next_avail.wrapping_add(1);
        self.put(AVAIL + 2, self.next_avail);
        barrier();
        regs.write(QUEUE_NOTIFY, self.index as u32);
    }

    /// The next chain the device has finished with: its head and how many bytes it wrote, if any.
    pub fn take_used(&mut self) -> Option<(u16, u32)> {
        barrier();
        if self.get::<u16>(USED + 2) == self.last_used {
            return None;
        }
        let at = USED + 4 + (self.last_used % QUEUE_SIZE) as usize * 8;
        let head = self.get::<u32>(at) as u16;
        let len = self.get::<u32>(at + 4);
        self.last_used = self.last_used.wrapping_add(1);
        Some((head, len))
    }

    /// The page's physical address plus `offset`: where a buffer in the rest of the page is, for a descriptor.
    pub fn paddr(&self, offset: usize) -> u64 {
        self.paddr + offset as u64
    }
}
