//! `lantern-net-driver` — [RFC-0035](../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)'s virtio-net driver
//! (QEMU's `-device virtio-net-device`).
//!
//! It moves whole Ethernet frames between the device and one client, `net`, over an RFC-0019 channel, and **parses none
//! of them**: what's in a frame is the stack's business, in a program with no DMA. Like `blk-driver`, it is trusted with
//! memory until there's an IOMMU, and that's why it does as little as it can.
//!
//! The device's interrupt is bound to `net`'s notification (`net::driver::BIT_RX`), not this program's: this program only
//! ever waits for a request. `net` drains received frames with `RECV` and then asks for `ACK`.
//!
//! Eight receive buffers, offered to the device at start and again as each is drained; one transmit buffer, reused once
//! the device has finished with it.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{status, Channel, RefuseInterlopers};
use lantern_abi::net::driver;
use lantern_abi::sys::{self, frame, irq, retype};
use lantern_abi::wire::MapPerms;
use lantern_virtio::{Queue, Regs, DESC_WRITE, QUEUE_SIZE};

// Granted by the loader (`src/system/loader.rs`).
const ENDPOINT: usize = 1;
const IRQ: usize = 2;
/// `net`'s notification, badged `net::driver::BIT_RX`: where the device's interrupt goes.
const NET_RX: usize = 3;
const DMA_MEMORY: usize = 4;
const SELF_VSPACE: usize = 5;
const FAILURE: usize = 6;
// Its own: the receive queue's page, the transmit queue's (with its buffer), and the receive buffers', two a page.
const RX_QUEUE: usize = 10;
const TX_QUEUE: usize = 11;
const RX_PAGES: usize = 12;
const RX_PAGE_COUNT: usize = QUEUE_SIZE as usize / 2;

const REGS: Regs = Regs(0x9500_0000);
const CHANNEL_VADDR: usize = 0x9000_0000;
const RX_QUEUE_VADDR: usize = 0x9600_0000;
const TX_QUEUE_VADDR: usize = 0x9600_1000;
const RX_PAGES_VADDR: usize = 0x9600_2000;
/// The transmit buffer, after the queue in its page.
const TX_BUFFER: usize = 1024;
/// Each receive buffer's half page.
const RX_STRIDE: usize = 2048;

const DEVICE_ID_NET: u32 = 1;
/// `VIRTIO_NET_F_MAC`: the device's address is in its configuration.
const F_MAC: u32 = 1 << 5;
/// `virtio_net_hdr` with `VERSION_1`: 12 bytes before every frame, all zero on transmit.
const NET_HEADER: usize = 12;
const FRAME_MAX: usize = 1514;
/// The net service's badge, its only client.
const NET: u64 = 1;

/// An `arg0` flag: the machine has no such device.
const ABSENT: usize = 1;

lantern_abi::entry!(run);

struct Device {
    rx: Queue,
    tx: Queue,
    rx_paddrs: [u64; RX_PAGE_COUNT],
    tx_busy: bool,
    mac: [u8; 6],
}

fn run(arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    // No device: the loader found none, so there's nothing to report, only every request to refuse.
    if arg0 & ABSENT != 0 {
        refuse();
    }
    let mut device = init().unwrap_or_else(|step| fail(step));
    // SAFETY: the loader mapped the channel shared with `net` read/write at CHANNEL_VADDR.
    let mut channel = unsafe { Channel::new(ENDPOINT, CHANNEL_VADDR as *mut u8) };
    let mut request = [0u8; FRAME_MAX];
    let mut reply = [0u8; FRAME_MAX];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if received.badge != NET {
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        }
        let Ok((op, len)) = channel.recv_request(received, &mut request, &mut RefuseInterlopers) else { continue };
        let (outcome, reply_len) = match op {
            driver::OP_SEND => (device.send(&request[..len]), 0),
            driver::OP_RECV => device.recv(&mut reply),
            driver::OP_ACK => {
                REGS.ack();
                let _ = irq::ack(IRQ);
                (status::OK, 0)
            }
            driver::OP_MAC => {
                reply[..6].copy_from_slice(&device.mac);
                (status::OK, 6)
            }
            _ => (status::INVALID, 0),
        };
        let _ = channel.reply(outcome, &reply[..reply_len], received.badge, &mut RefuseInterlopers);
    }
}

fn init() -> Result<Device, usize> {
    if lantern_virtio::begin(REGS, DEVICE_ID_NET, F_MAC)? & F_MAC == 0 {
        return Err(9);
    }
    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    let page = |cap: usize, vaddr: usize| -> Result<u64, usize> {
        retype::frame_small(DMA_MEMORY, cap).map_err(|_| 2usize)?;
        frame::map(cap, SELF_VSPACE, vaddr, rw).map_err(|_| 3usize)?;
        frame::address(cap).map(|a| a as u64).map_err(|_| 4usize)
    };
    let rx_paddr = page(RX_QUEUE, RX_QUEUE_VADDR)?;
    let tx_paddr = page(TX_QUEUE, TX_QUEUE_VADDR)?;
    let mut rx_paddrs = [0u64; RX_PAGE_COUNT];
    for (i, p) in rx_paddrs.iter_mut().enumerate() {
        *p = page(RX_PAGES + i, RX_PAGES_VADDR + i * 0x1000)?;
    }
    let mut rx = Queue::new(REGS, 0, RX_QUEUE_VADDR, rx_paddr)?;
    let tx = Queue::new(REGS, 1, TX_QUEUE_VADDR, tx_paddr)?;
    let mac = core::array::from_fn(|i| REGS.config_byte(i));
    lantern_virtio::finish(REGS);
    for head in 0..QUEUE_SIZE {
        offer_rx(&mut rx, &rx_paddrs, head);
    }
    irq::set_notification(IRQ, NET_RX).map_err(|_| 8usize)?;
    Ok(Device { rx, tx, rx_paddrs, tx_busy: false, mac })
}

/// Receive buffer `i`: its half of a page, as an address the device writes to.
fn rx_paddr(paddrs: &[u64; RX_PAGE_COUNT], i: u16) -> u64 {
    paddrs[i as usize / 2] + (i as usize % 2 * RX_STRIDE) as u64
}

fn rx_buffer(i: u16) -> &'static [u8] {
    let at = RX_PAGES_VADDR + i as usize / 2 * 0x1000 + i as usize % 2 * RX_STRIDE;
    // SAFETY: inside the receive pages, mapped read/write at RX_PAGES_VADDR; the device has finished with buffer `i`, since
    // it's in the used ring, and it isn't offered again until this copy is done.
    unsafe { core::slice::from_raw_parts(at as *const u8, NET_HEADER + FRAME_MAX) }
}

fn offer_rx(rx: &mut Queue, paddrs: &[u64; RX_PAGE_COUNT], head: u16) {
    rx.descriptor(head, rx_paddr(paddrs, head), (NET_HEADER + FRAME_MAX) as u32, DESC_WRITE, 0);
    rx.offer(REGS, head);
}

impl Device {
    /// Transmits one frame, once the device has finished with the last.
    fn send(&mut self, frame: &[u8]) -> u16 {
        if frame.len() < 14 || frame.len() > FRAME_MAX {
            return status::INVALID;
        }
        if self.tx_busy {
            // The device takes a frame almost at once; this bounds a device that stopped.
            let mut spins = 0u32;
            while self.tx.take_used().is_none() {
                spins += 1;
                if spins > 10_000_000 {
                    return status::FAILED;
                }
                core::hint::spin_loop();
            }
        }
        // SAFETY: the transmit buffer is inside the transmit queue's page, mapped read/write at TX_QUEUE_VADDR, and the
        // device has finished with it.
        let buffer = unsafe { core::slice::from_raw_parts_mut((TX_QUEUE_VADDR + TX_BUFFER) as *mut u8, NET_HEADER + FRAME_MAX) };
        buffer[..NET_HEADER].fill(0);
        buffer[NET_HEADER..NET_HEADER + frame.len()].copy_from_slice(frame);
        self.tx.descriptor(0, self.tx.paddr(TX_BUFFER), (NET_HEADER + frame.len()) as u32, 0, 0);
        self.tx.offer(REGS, 0);
        self.tx_busy = true;
        status::OK
    }

    /// The oldest frame the device has received, or nothing.
    fn recv(&mut self, out: &mut [u8]) -> (u16, usize) {
        let Some((head, len)) = self.rx.take_used() else { return (status::OK, 0) };
        if head >= QUEUE_SIZE {
            return (status::FAILED, 0);
        }
        let len = (len as usize).saturating_sub(NET_HEADER).min(FRAME_MAX);
        out[..len].copy_from_slice(&rx_buffer(head)[NET_HEADER..NET_HEADER + len]);
        offer_rx(&mut self.rx, &self.rx_paddrs, head);
        (status::OK, len)
    }
}

/// Reports the step that failed, then refuses every request: `net` sees a device that answers nothing.
/// Refuses every request, for good: a client sees a device that answers nothing.
fn refuse() -> ! {
    loop {
        if sys::recv(ENDPOINT).is_ok() {
            let _ = sys::reply_with_label(status::FAILED as u32, [0, 0, 0]);
        }
    }
}

fn fail(step: usize) -> ! {
    let _ = sys::signal_with(FAILURE, step, 0);
    loop {
        if sys::recv(ENDPOINT).is_ok() {
            let _ = sys::reply_with_label(status::FAILED as u32, [0, 0, 0]);
        }
    }
}
