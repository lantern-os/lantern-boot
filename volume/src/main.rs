//! `lantern-volume` — [RFC-0031](../../lantern-rfcs/rfcs/0031-storage-a-block-driver-and-the-store-on-disk.md)'s volume:
//! the block driver's one client, which reads the disk's partition table and serves each client exactly its own
//! partition.
//!
//! | Badge | Partition | Access |
//! |---|---|---|
//! | `LAUNCHER`, `BINDER` | packages | read |
//! | `STORE` | store | read and write |
//! | `POLICY` | policy store's log | read and write |
//!
//! A client names sectors from its partition's start, checked against its length, so it can't name one outside it. The
//! partition table is untrusted: it's parsed here (`lantern_abi::gpt`), in a program with no DMA and no mint authority,
//! and if it doesn't check out, every client is refused.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::block::{self, badge, Client, MAX_BYTES, SECTOR};
use lantern_abi::frame::{status, Channel, RefuseInterlopers};
use lantern_abi::gpt::{self, Extent, Layout};
use lantern_abi::sys;
use lantern_volume::{access, route};

// Granted by the loader (`src/system/loader.rs`).
const ENDPOINT: usize = 1;
const DRIVER: usize = 2;
const FAILURE: usize = 3;

const DRIVER_CHANNEL_VADDR: usize = 0x9000_0000;
/// Client `b`'s channel is at `CLIENT_CHANNEL_VADDR + (b - 1) × 4 KiB`.
const CLIENT_CHANNEL_VADDR: usize = 0x9001_0000;

lantern_abi::entry!(run);

fn run(_arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    // SAFETY: the loader mapped the channel shared with the driver read/write at DRIVER_CHANNEL_VADDR.
    let mut driver = Client { channel: unsafe { Channel::new(DRIVER, DRIVER_CHANNEL_VADDR as *mut u8) } };
    let layout = read_layout(&mut driver);
    // SAFETY: the loader mapped each client's channel read/write, one page apart, from CLIENT_CHANNEL_VADDR.
    let mut channels: [Channel; badge::CLIENTS] =
        core::array::from_fn(|c| unsafe { Channel::new(ENDPOINT, (CLIENT_CHANNEL_VADDR + c * 0x1000) as *mut u8) });
    let mut request = [0u8; block::HEADER + MAX_BYTES];
    let mut reply = [0u8; MAX_BYTES];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        let Some((extent, writable)) = layout.and_then(|l| access(l, received.badge)) else {
            // No channel to write a reply to: the label alone refuses it.
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        };
        let channel = &mut channels[received.badge as usize - 1];
        let Ok((op, len)) = channel.recv_request(received, &mut request, &mut RefuseInterlopers) else { continue };
        let (outcome, reply_len) = serve(&mut driver, extent, writable, op, &request[..len], &mut reply);
        let _ = channel.reply(outcome, &reply[..reply_len], received.badge, &mut RefuseInterlopers);
    }
}

fn serve(driver: &mut Client, extent: Extent, writable: bool, op: u16, request: &[u8], reply: &mut [u8]) -> (u16, usize) {
    if op == block::OP_INFO {
        reply[..8].copy_from_slice(&extent.sectors.to_le_bytes());
        return (status::OK, 8);
    }
    let Some((first, count)) = block::decode_range(request) else { return (status::INVALID, 0) };
    let on_disk = match route(extent, writable, op, first, count) {
        Ok(sector) => sector,
        Err(refused) => return (refused, 0),
    };
    let bytes = count * SECTOR;
    let result = match op {
        block::OP_READ => driver.read(on_disk, &mut reply[..bytes]).map(|()| bytes),
        _ if request.len() == block::HEADER + bytes => driver.write(on_disk, &request[block::HEADER..]).map(|()| 0),
        _ => return (status::INVALID, 0),
    };
    match result {
        Ok(len) => (status::OK, len),
        Err(_) => (status::FAILED, 0),
    }
}

/// The disk's LanternOS partitions, or `None` if its table doesn't check out, or can't be read.
fn read_layout(driver: &mut Client) -> Option<Layout> {
    let sectors = driver.sectors().ok()?;
    let mut header = [0u8; SECTOR];
    driver.read(gpt::HEADER_LBA, &mut header).ok()?;
    let mut entries = [0u8; gpt::ENTRY_COUNT * gpt::ENTRY_SIZE];
    for (i, chunk) in entries.chunks_mut(MAX_BYTES).enumerate() {
        driver.read(gpt::ENTRIES_LBA + (i * block::MAX_SECTORS) as u64, chunk).ok()?;
    }
    gpt::parse(&header, &entries, sectors)
}
