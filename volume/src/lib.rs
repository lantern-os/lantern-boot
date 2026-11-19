//! The volume's decision ([RFC-0031](../../lantern-rfcs/rfcs/0031-storage-a-block-driver-and-the-store-on-disk.md)):
//! which partition each badge reaches, and where on the disk a request lands, with no syscalls in it, so it can be
//! tested on a host. `src/main.rs` is the program around it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use lantern_abi::block::{self, badge};
use lantern_abi::frame::status;
use lantern_abi::gpt::{Extent, Layout};

/// The partition a badge reaches, and whether it may write. Any other badge reaches nothing.
pub fn access(layout: Layout, client: u64) -> Option<(Extent, bool)> {
    match client {
        badge::LAUNCHER | badge::BINDER => Some((layout.packages, false)),
        badge::STORE => Some((layout.store, true)),
        // RFC-0032: the policy store's log, on a disk that has a partition for it.
        badge::POLICY => layout.policy.map(|p| (p, true)),
        // RFC-0034: the model, read-only, to the inference service, on a disk that has one.
        badge::MODELS => layout.models.map(|m| (m, false)),
        // RFC-0035: the wallet's sealed root, read and write, on a disk that has a partition for it.
        badge::WALLET => layout.wallet.map(|w| (w, true)),
        // RFC-0038: the audit archive, read and write, for the archiver alone.
        badge::ARCHIVE => layout.archive.map(|a| (a, true)),
        _ => None,
    }
}

/// Where a `READ` or `WRITE` of `count` sectors from the partition's sector `first` lands on the disk, or the RFC-0019
/// status refusing it: outside the partition, or a write to a read-only one.
pub fn route(extent: Extent, writable: bool, op: u16, first: u64, count: usize) -> Result<u64, u16> {
    if !block::within(first, count, extent.sectors) {
        return Err(status::INVALID);
    }
    match op {
        block::OP_READ => Ok(extent.first + first),
        block::OP_WRITE if writable => Ok(extent.first + first),
        block::OP_WRITE => Err(status::ACCESS),
        _ => Err(status::INVALID),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: Layout = Layout {
        packages: Extent { first: 2048, sectors: 100 },
        store: Extent { first: 4096, sectors: 64 },
        policy: Some(Extent { first: 8192, sectors: 4096 }),
        models: Some(Extent { first: 16384, sectors: 8192 }),
        wallet: Some(Extent { first: 24576, sectors: 64 }),
        archive: Some(Extent { first: 24640, sectors: 1152 }),
    };

    #[test]
    fn each_badge_reaches_its_own_partition_and_no_other() {
        assert_eq!(access(LAYOUT, badge::LAUNCHER), Some((LAYOUT.packages, false)));
        assert_eq!(access(LAYOUT, badge::BINDER), Some((LAYOUT.packages, false)));
        assert_eq!(access(LAYOUT, badge::STORE), Some((LAYOUT.store, true)));
        assert_eq!(access(LAYOUT, badge::POLICY), Some((LAYOUT.policy.unwrap(), true)));
        assert_eq!(access(Layout { policy: None, ..LAYOUT }, badge::POLICY), None, "no partition, no access");
        assert_eq!(access(LAYOUT, badge::MODELS), Some((LAYOUT.models.unwrap(), false)), "the model is read-only");
        assert_eq!(access(Layout { models: None, ..LAYOUT }, badge::MODELS), None);
        assert_eq!(access(LAYOUT, badge::WALLET), Some((LAYOUT.wallet.unwrap(), true)));
        assert_eq!(access(Layout { wallet: None, ..LAYOUT }, badge::WALLET), None);
        assert_eq!(access(LAYOUT, badge::ARCHIVE), Some((LAYOUT.archive.unwrap(), true)));
        assert_eq!(access(Layout { archive: None, ..LAYOUT }, badge::ARCHIVE), None);
        for other in [0, 8, u64::MAX] {
            assert_eq!(access(LAYOUT, other), None);
        }
    }

    #[test]
    fn a_request_lands_inside_its_partition_or_is_refused() {
        let store = LAYOUT.store;
        assert_eq!(route(store, true, block::OP_READ, 0, 8), Ok(4096));
        assert_eq!(route(store, true, block::OP_WRITE, 56, 8), Ok(4152), "the last 8 sectors");
        assert_eq!(route(store, true, block::OP_READ, 57, 8), Err(status::INVALID), "one past the end");
        assert_eq!(route(store, true, block::OP_READ, u64::MAX, 1), Err(status::INVALID), "wraps");
        // The packages partition sits right before the store's: its last sector is as far as a packages reader gets.
        assert_eq!(route(LAYOUT.packages, false, block::OP_READ, 99, 1), Ok(2147));
        assert_eq!(route(LAYOUT.packages, false, block::OP_READ, 100, 1), Err(status::INVALID));
        assert_eq!(route(LAYOUT.packages, false, block::OP_WRITE, 0, 1), Err(status::ACCESS), "read-only");
        assert_eq!(route(store, true, 99, 0, 1), Err(status::INVALID));
    }
}
