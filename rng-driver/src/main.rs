//! `lantern-rng-driver` — [RFC-0035](../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)'s source of
//! randomness: a virtio-rng device (QEMU's `-device virtio-rng-device`), served to one client, the wallet, 24 bytes a
//! call.
//!
//! The system had no randomness before this. The wallet needs it for its secret root, made once, and for every
//! handshake's ephemeral key. A board with a hardware generator gets a driver for it behind the same protocol
//! (`lantern_abi::net::random`).
//!
//! It holds the device's register page, its `IrqHandler`, a DMA `Untyped` for one page (its queue and buffer), and its own
//! VSpace. It is trusted with memory, as every DMA driver is until there's an IOMMU.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::status;
use lantern_abi::sys::{self, frame, irq, retype};
use lantern_abi::wire::MapPerms;
use lantern_virtio::{Queue, Regs, DESC_WRITE};

// Granted by the loader (`src/system/loader.rs`).
const ENDPOINT: usize = 1;
const IRQ: usize = 2;
const NOTIFY: usize = 3;
const DMA_MEMORY: usize = 4;
const SELF_VSPACE: usize = 5;
const FAILURE: usize = 6;
// Its own.
const PAGE: usize = 10;

const REGS: Regs = Regs(0x9500_0000);
const PAGE_VADDR: usize = 0x9600_0000;
/// Where the device writes, after the queue.
const BUFFER: usize = 1024;
/// The wallet's badge, its only client.
const WALLET: u64 = 1;
const DEVICE_ID_RNG: u32 = 4;

/// An `arg0` flag: the machine has no such device.
const ABSENT: usize = 1;

lantern_abi::entry!(run);

fn run(arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    // No device: the loader found none, so there's nothing to report, only every request to refuse.
    if arg0 & ABSENT != 0 {
        refuse();
    }
    let mut queue = init().unwrap_or_else(|step| fail(step));
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if received.badge != WALLET {
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        }
        let _ = lantern_abi::net::reply_random(fill(&mut queue));
    }
}

fn init() -> Result<Queue, usize> {
    lantern_virtio::begin(REGS, DEVICE_ID_RNG, 0)?;
    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    retype::frame_small(DMA_MEMORY, PAGE).map_err(|_| 2usize)?;
    frame::map(PAGE, SELF_VSPACE, PAGE_VADDR, rw).map_err(|_| 3usize)?;
    let paddr = frame::address(PAGE).map_err(|_| 4usize)? as u64;
    let queue = Queue::new(REGS, 0, PAGE_VADDR, paddr)?;
    lantern_virtio::finish(REGS);
    irq::set_notification(IRQ, NOTIFY).map_err(|_| 8usize)?;
    Ok(queue)
}

/// 24 bytes from the device, asking again until it has given that many. `None` if it stops answering.
fn fill(queue: &mut Queue) -> Option<[u8; 24]> {
    let mut out = [0u8; 24];
    let mut have = 0;
    while have < out.len() {
        let want = out.len() - have;
        queue.descriptor(0, queue.paddr(BUFFER), want as u32, DESC_WRITE, 0);
        queue.offer(REGS, 0);
        let got = loop {
            if let Some((_, len)) = queue.take_used() {
                break len as usize;
            }
            sys::wait(NOTIFY).ok()?;
            REGS.ack();
            let _ = irq::ack(IRQ);
        };
        let got = got.min(want);
        // SAFETY: the buffer is inside the DMA page mapped at PAGE_VADDR, which the device has finished writing.
        let written = unsafe { core::slice::from_raw_parts((PAGE_VADDR + BUFFER) as *const u8, got) };
        out[have..have + got].copy_from_slice(written);
        have += got;
    }
    Some(out)
}

/// Refuses every request, for good: a client sees a device that answers nothing.
fn refuse() -> ! {
    loop {
        if sys::recv(ENDPOINT).is_ok() {
            let _ = sys::reply_with_label(status::FAILED as u32, [0, 0, 0]);
        }
    }
}

/// Reports the step that failed, then refuses every request: the wallet then has no randomness, and makes no root.
fn fail(step: usize) -> ! {
    let _ = sys::signal_with(FAILURE, step, 0);
    refuse()
}
