//! `lantern-blk-driver` — [RFC-0031](../../lantern-rfcs/rfcs/0031-storage-a-block-driver-and-the-store-on-disk.md)'s
//! virtio-blk driver.
//!
//! It holds one virtio-mmio device's 4 KiB register page, its `IrqHandler`, a DMA `Untyped` for its queue and data
//! buffer, and its own VSpace to map them. It serves raw sectors over an RFC-0019 channel to one client, under one badge:
//! the volume's. **It parses nothing from the disk**: what's on it is the volume's business.
//!
//! **It is trusted with all memory.** QEMU `virt` has no IOMMU, so the device reaches whatever physical address the driver
//! writes into a descriptor. It writes only the addresses of its own two DMA Frames, which only a DMA `Untyped` can
//! reveal, but nothing below it enforces that. RFC-0023's checklist carries the row.
//!
//! virtio 1.x over MMIO (version 2: QEMU needs `-global virtio-mmio.force-legacy=false`), one split virtqueue of 8
//! descriptors, one request at a time, sleeping on its interrupt. A `WRITE` is followed by a `FLUSH` when the device
//! offers one, and is answered `OK` only once both completed.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{fence, Ordering};

use lantern_abi::block::{self, badge, MAX_BYTES, SECTOR};
use lantern_abi::frame::{status, Channel, RefuseInterlopers};
use lantern_abi::sys::{self, frame, irq, retype};
use lantern_abi::wire::MapPerms;

// Granted by the loader (`src/system/loader.rs`).
const ENDPOINT: usize = 1;
const IRQ: usize = 2;
const NOTIFY: usize = 3;
const DMA_MEMORY: usize = 4;
const SELF_VSPACE: usize = 5;
const FAILURE: usize = 6;
// Its own.
const QUEUE_FRAME: usize = 10;
const DATA_FRAME: usize = 11;

const REGS_VADDR: usize = 0x9500_0000;
const CHANNEL_VADDR: usize = 0x9000_0000;
const QUEUE_VADDR: usize = 0x9600_0000;
const DATA_VADDR: usize = 0x9600_1000;

/// virtio-mmio registers.
const MAGIC: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE_ID: usize = 0x008;
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS: usize = 0x070;
const QUEUE_DESC: usize = 0x080;
const QUEUE_DRIVER: usize = 0x090;
const QUEUE_DEVICE: usize = 0x0a0;
const CONFIG_CAPACITY: usize = 0x100;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
/// Feature bits, by 32-bit word.
const F_FLUSH: u32 = 1 << 9;
const F_VERSION_1: u32 = 1 << 0; // word 1, bit 32 overall.

const QUEUE_SIZE: u16 = 8;
/// Where each part of the queue lives in its page: the descriptors, the driver ("available") ring, the device ("used")
/// ring, and one request's header and status byte.
const DESC: usize = 0;
const AVAIL: usize = 128;
const USED: usize = 256;
const REQ_HEADER: usize = 512;
const REQ_STATUS: usize = 528;

const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

lantern_abi::entry!(run);

fn reg(offset: usize) -> *mut u32 {
    (REGS_VADDR + offset) as *mut u32
}

fn read(offset: usize) -> u32 {
    // SAFETY: the loader mapped the device's 4 KiB register page read/write at REGS_VADDR for this program's whole life,
    // and these are its 32-bit registers.
    unsafe { core::ptr::read_volatile(reg(offset)) }
}

fn write(offset: usize, value: u32) {
    // SAFETY: as `read`.
    unsafe { core::ptr::write_volatile(reg(offset), value) }
}

/// Orders every memory and device access before it against every one after: the device reads the queue by DMA.
fn barrier() {
    fence(Ordering::SeqCst);
    // SAFETY: a fence has no operands and no effect beyond ordering.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack))
    };
}

fn put<T: Copy>(at: usize, value: T) {
    // SAFETY: `at` is inside the queue page, mapped read/write at QUEUE_VADDR, and suitably aligned for `T` by the layout
    // above. The device reads it by DMA, so it's written volatile.
    unsafe { core::ptr::write_volatile((QUEUE_VADDR + at) as *mut T, value) }
}

fn get<T: Copy>(at: usize) -> T {
    // SAFETY: as `put`.
    unsafe { core::ptr::read_volatile((QUEUE_VADDR + at) as *const T) }
}

fn data() -> &'static mut [u8] {
    // SAFETY: the data page is mapped read/write at DATA_VADDR, and only this single thread touches it, between requests.
    unsafe { core::slice::from_raw_parts_mut(DATA_VADDR as *mut u8, MAX_BYTES) }
}

struct Device {
    queue_paddr: u64,
    data_paddr: u64,
    flush: bool,
    capacity: u64,
    next_avail: u16,
    last_used: u16,
}

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    let mut device = init().unwrap_or_else(|step| fail(step));
    // SAFETY: the loader mapped the channel shared with the volume read/write at CHANNEL_VADDR.
    let mut channel = unsafe { Channel::new(ENDPOINT, CHANNEL_VADDR as *mut u8) };
    let mut request = [0u8; block::HEADER + MAX_BYTES];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if received.badge != badge::VOLUME {
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        }
        let Ok((op, len)) = channel.recv_request(received, &mut request, &mut RefuseInterlopers) else { continue };
        let (outcome, reply_len) = serve(&mut device, op, &request[..len]);
        let _ = channel.reply(outcome, &data()[..reply_len], received.badge, &mut RefuseInterlopers);
    }
}

fn serve(device: &mut Device, op: u16, request: &[u8]) -> (u16, usize) {
    if op == block::OP_INFO {
        data()[..8].copy_from_slice(&device.capacity.to_le_bytes());
        return (status::OK, 8);
    }
    let Some((first, count)) = block::decode_range(request) else { return (status::INVALID, 0) };
    if !block::within(first, count, device.capacity) {
        return (status::INVALID, 0);
    }
    let bytes = count * SECTOR;
    match op {
        block::OP_READ => match device.transfer(T_IN, first, bytes) {
            true => (status::OK, bytes),
            false => (status::FAILED, 0),
        },
        block::OP_WRITE if request.len() == block::HEADER + bytes => {
            data()[..bytes].copy_from_slice(&request[block::HEADER..]);
            let done = device.transfer(T_OUT, first, bytes) && (!device.flush || device.transfer(T_FLUSH, 0, 0));
            (if done { status::OK } else { status::FAILED }, 0)
        }
        _ => (status::INVALID, 0),
    }
}

/// Brings the device up (virtio 1.1, §3.1.1 and §4.2.3), or says at which step it failed.
fn init() -> Result<Device, usize> {
    if read(MAGIC) != 0x7472_6976 || read(VERSION) != 2 || read(DEVICE_ID) != 2 {
        return Err(1);
    }
    for (cap, vaddr) in [(QUEUE_FRAME, QUEUE_VADDR), (DATA_FRAME, DATA_VADDR)] {
        let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
        retype::frame_small(DMA_MEMORY, cap).map_err(|_| 2usize)?;
        frame::map(cap, SELF_VSPACE, vaddr, rw).map_err(|_| 3usize)?;
    }
    let queue_paddr = frame::address(QUEUE_FRAME).map_err(|_| 4usize)? as u64;
    let data_paddr = frame::address(DATA_FRAME).map_err(|_| 4usize)? as u64;

    write(STATUS, 0);
    write(STATUS, STATUS_ACKNOWLEDGE);
    write(STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    write(DEVICE_FEATURES_SEL, 1);
    if read(DEVICE_FEATURES) & F_VERSION_1 == 0 {
        return Err(5);
    }
    write(DEVICE_FEATURES_SEL, 0);
    let flush = read(DEVICE_FEATURES) & F_FLUSH != 0;
    write(DRIVER_FEATURES_SEL, 0);
    write(DRIVER_FEATURES, if flush { F_FLUSH } else { 0 });
    write(DRIVER_FEATURES_SEL, 1);
    write(DRIVER_FEATURES, F_VERSION_1);
    write(STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if read(STATUS) & STATUS_FEATURES_OK == 0 {
        return Err(6);
    }

    write(QUEUE_SEL, 0);
    if read(QUEUE_READY) != 0 || read(QUEUE_NUM_MAX) < QUEUE_SIZE as u32 {
        return Err(7);
    }
    write(QUEUE_NUM, QUEUE_SIZE as u32);
    for (reg, offset) in [(QUEUE_DESC, DESC), (QUEUE_DRIVER, AVAIL), (QUEUE_DEVICE, USED)] {
        let paddr = queue_paddr + offset as u64;
        write(reg, paddr as u32);
        write(reg + 4, (paddr >> 32) as u32);
    }
    write(QUEUE_READY, 1);
    write(STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    if irq::set_notification(IRQ, NOTIFY).is_err() {
        return Err(8);
    }
    let capacity = read(CONFIG_CAPACITY) as u64 | (read(CONFIG_CAPACITY + 4) as u64) << 32;
    Ok(Device { queue_paddr, data_paddr, flush, capacity, next_avail: 0, last_used: 0 })
}

impl Device {
    /// One request: `T_IN` reads `bytes` from sector `first` into the data page, `T_OUT` writes them from it, `T_FLUSH`
    /// makes every completed write durable. `true` once the device answered success.
    fn transfer(&mut self, kind: u32, first: u64, bytes: usize) -> bool {
        put(REQ_HEADER, kind);
        put(REQ_HEADER + 4, 0u32);
        put(REQ_HEADER + 8, first);
        put(REQ_STATUS, 0xffu8);
        let descriptor = |i: usize, addr: u64, len: u32, flags: u16, next: u16| {
            put(DESC + i * 16, addr);
            put(DESC + i * 16 + 8, len);
            put(DESC + i * 16 + 12, flags);
            put(DESC + i * 16 + 14, next);
        };
        descriptor(0, self.queue_paddr + REQ_HEADER as u64, 16, DESC_NEXT, if bytes > 0 { 1 } else { 2 });
        if bytes > 0 {
            let flags = if kind == T_IN { DESC_NEXT | DESC_WRITE } else { DESC_NEXT };
            descriptor(1, self.data_paddr, bytes as u32, flags, 2);
        }
        descriptor(2, self.queue_paddr + REQ_STATUS as u64, 1, DESC_WRITE, 0);

        put(AVAIL + 4 + (self.next_avail % QUEUE_SIZE) as usize * 2, 0u16);
        barrier();
        self.next_avail = self.next_avail.wrapping_add(1);
        put(AVAIL + 2, self.next_avail);
        barrier();
        write(QUEUE_NOTIFY, 0);

        // Wait for the device to put it in the used ring. An interrupt may already have come and gone, so look first.
        while get::<u16>(USED + 2) == self.last_used {
            if sys::wait(NOTIFY).is_err() {
                return false;
            }
            write(INTERRUPT_ACK, read(INTERRUPT_STATUS));
            let _ = irq::ack(IRQ);
        }
        barrier();
        self.last_used = self.last_used.wrapping_add(1);
        get::<u8>(REQ_STATUS) == 0
    }
}

fn fail(step: usize) -> ! {
    let _ = sys::signal_with(FAILURE, step, 0);
    loop {
        let _ = sys::wait(NOTIFY);
    }
}
