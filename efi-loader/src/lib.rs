//! The EFI loader's decision ([RFC-0032](../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)): where each part of
//! the boot image goes, and whether it may go there at all, with no firmware calls in it, so it can be tested on a host.
//! `src/main.rs` is the UEFI program around it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Where the kernel is linked (`lantern-boot/linker.ld`): its two megapages, 2 MiB above the start of QEMU `virt`'s RAM.
/// The image is position-independent ([RFC-0039](../../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)): the
/// loader copies it to any 2 MiB-aligned range the firmware gives it, and the kernel applies its own relocations for the
/// difference.
pub const KERNEL_BASE: u64 = 0x8020_0000;
pub const KERNEL_SIZE: u64 = 4 << 20;
/// The alignment the kernel's range needs: a megapage, which the kernel maps itself with.
pub const KERNEL_ALIGN: u64 = 2 << 20;

/// The lowest megapage-aligned base for the kernel's range inside one of `free`'s `(start, bytes)` runs, the firmware's
/// conventional memory. Lowest, so the RAM above it stays one run for the kernel's general memory.
pub fn lowest_fit(free: impl Iterator<Item = (u64, u64)>) -> Option<u64> {
    free.filter_map(|(start, bytes)| {
        let base = aligned_base(start)?;
        (base.checked_add(KERNEL_SIZE)? <= start.checked_add(bytes)?).then_some(base)
    })
    .min()
}

/// The hand-off to the kernel in `a2` and `a3` (RFC-0039): this magic, `b"LNTNEFI1"` little-endian, then a pointer to
/// a [`Reserved`] table. Any other `a2` means there's no table, as when OpenSBI starts the kernel directly.
pub const HANDOFF_MAGIC: u64 = u64::from_le_bytes(*b"LNTNEFI1");
/// The most ranges the table holds: one page, less its count word, of `(base, size)` pairs.
pub const MAX_RESERVED: usize = 255;

/// What the firmware's memory map says isn't free once boot services are gone: every descriptor but the loader's own
/// memory, boot services' (which `ExitBootServices` frees) and conventional memory. Firmware runtime services, reserved
/// and non-volatile memory, ACPI's, MMIO: all kept away from the kernel. Merged where adjacent. `None` if it doesn't fit.
pub fn reserved_ranges(descriptors: impl Iterator<Item = (u32, u64, u64)>, out: &mut [(u64, u64)]) -> Option<usize> {
    const FREE_AFTER_EXIT: [u32; 5] = [1, 2, 3, 4, 7];
    let mut n = 0usize;
    for (kind, start, pages) in descriptors {
        if FREE_AFTER_EXIT.contains(&kind) || pages == 0 {
            continue;
        }
        let size = pages.checked_mul(4096)?;
        if n > 0 && out[n - 1].0.checked_add(out[n - 1].1) == Some(start) {
            out[n - 1].1 = out[n - 1].1.checked_add(size)?;
            continue;
        }
        *out.get_mut(n)? = (start, size);
        n += 1;
    }
    Some(n)
}

/// The most a device tree may be, for the loader's copy: real ones are a few KiB to a few hundred.
pub const MAX_DEVICE_TREE: usize = 1 << 20;

/// A device tree's size from its first 8 bytes, if they're a device tree's header and it's no bigger than
/// [`MAX_DEVICE_TREE`]. The kernel checks the whole tree; this only bounds the copy.
pub fn device_tree_size(head: [u8; 8]) -> Option<usize> {
    if head[..4] != [0xd0, 0x0d, 0xfe, 0xed] {
        return None;
    }
    let size = u32::from_be_bytes(head[4..].try_into().ok()?) as usize;
    (40..=MAX_DEVICE_TREE).contains(&size).then_some(size)
}

/// The 2 MiB-aligned start inside a range of `KERNEL_SIZE + KERNEL_ALIGN` bytes the firmware allocated at `at`.
pub fn aligned_base(at: u64) -> Option<u64> {
    at.checked_add(KERNEL_ALIGN - 1).map(|v| v & !(KERNEL_ALIGN - 1))
}

/// One part of the boot image to copy: the file's bytes `[offset, offset + filesz)` to `at` bytes into the kernel's range,
/// then zeros to `memsz`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Copy {
    pub at: usize,
    pub offset: usize,
    pub filesz: usize,
    pub memsz: usize,
}

/// The most loadable segments the boot image may have.
pub const MAX_SEGMENTS: usize = 8;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Why the boot image can't be placed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    NotRiscvElf,
    /// A segment outside `[KERNEL_BASE, KERNEL_BASE + KERNEL_SIZE)`, or whose bytes aren't all in the file.
    OutOfRange,
    TooManySegments,
    /// The entry point isn't inside a loaded segment.
    BadEntry,
}

/// The boot image's entry point, at its link address, and its copies, all checked to land inside the kernel's linked range
/// and to come from inside `elf`. A position-independent image (`ET_DYN`) and a fixed one (`ET_EXEC`) are both accepted:
/// the kernel relocates itself.
pub fn plan(elf: &[u8]) -> Result<(u64, [Option<Copy>; MAX_SEGMENTS]), Refused> {
    let ok = elf.get(..4) == Some(b"\x7fELF") && elf.get(4) == Some(&2) && elf.get(5) == Some(&1);
    if !ok || !matches!(u16_at(elf, 16), Some(2 | 3)) || u16_at(elf, 18) != Some(243) {
        return Err(Refused::NotRiscvElf);
    }
    let bad = Refused::NotRiscvElf;
    let entry = u64_at(elf, 24).ok_or(bad)?;
    let phoff = u64_at(elf, 32).ok_or(bad)? as usize;
    let (phentsize, phnum) = (u16_at(elf, 54).ok_or(bad)? as usize, u16_at(elf, 56).ok_or(bad)? as usize);
    let mut copies = [None; MAX_SEGMENTS];
    let mut n = 0;
    let mut entry_inside = false;
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize).ok_or(bad)?).ok_or(bad)?;
        if u32_at(elf, ph).ok_or(bad)? != 1 {
            continue;
        }
        let (offset, paddr) = (u64_at(elf, ph + 8).ok_or(bad)?, u64_at(elf, ph + 24).ok_or(bad)?);
        let (filesz, memsz) = (u64_at(elf, ph + 32).ok_or(bad)?, u64_at(elf, ph + 40).ok_or(bad)?);
        let inside = paddr >= KERNEL_BASE
            && filesz <= memsz
            && paddr.checked_add(memsz).is_some_and(|end| end <= KERNEL_BASE + KERNEL_SIZE)
            && offset.checked_add(filesz).is_some_and(|end| end <= elf.len() as u64);
        if !inside {
            return Err(Refused::OutOfRange);
        }
        if n == MAX_SEGMENTS {
            return Err(Refused::TooManySegments);
        }
        entry_inside |= (paddr..paddr + memsz).contains(&entry);
        copies[n] = Some(Copy {
            at: (paddr - KERNEL_BASE) as usize,
            offset: offset as usize,
            filesz: filesz as usize,
            memsz: memsz as usize,
        });
        n += 1;
    }
    if !entry_inside {
        return Err(Refused::BadEntry);
    }
    Ok((entry, copies))
}

/// Applies `copies` from `elf` into `kernel`, the kernel's whole range: each segment's bytes, then zeros.
pub fn place(elf: &[u8], copies: &[Option<Copy>], kernel: &mut [u8]) {
    for c in copies.iter().flatten() {
        kernel[c.at..c.at + c.filesz].copy_from_slice(&elf[c.offset..c.offset + c.filesz]);
        kernel[c.at + c.filesz..c.at + c.memsz].fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// An ELF64 RISC-V executable with these `(paddr, filesz, memsz)` segments, each one's bytes `0x11 * (i + 1)`.
    fn elf(entry: u64, segments: &[(u64, u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 0x1000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&243u16.to_le_bytes());
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for (i, &(paddr, filesz, memsz)) in segments.iter().enumerate() {
            let at = 64 + i * 56;
            let offset = b.len() as u64;
            b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            b[at + 16..at + 24].copy_from_slice(&paddr.to_le_bytes());
            b[at + 24..at + 32].copy_from_slice(&paddr.to_le_bytes());
            b[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            b[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            b.extend(std::iter::repeat_n(0x11 * (i as u8 + 1), filesz as usize));
        }
        b
    }

    #[test]
    fn a_boot_image_is_placed_where_it_was_linked_with_its_bss_zeroed() {
        let image = elf(KERNEL_BASE, &[(KERNEL_BASE, 16, 16), (KERNEL_BASE + 0x2000, 4, 0x100)]);
        let (entry, copies) = plan(&image).unwrap();
        assert_eq!(entry, KERNEL_BASE);
        let mut kernel = vec![0xee; KERNEL_SIZE as usize];
        place(&image, &copies, &mut kernel);
        assert_eq!(&kernel[..16], &[0x11; 16]);
        assert_eq!(&kernel[0x2000..0x2004], &[0x22; 4]);
        assert!(kernel[0x2004..0x2100].iter().all(|&b| b == 0), "bss");
        assert_eq!(kernel[0x2100], 0xee, "nothing past the segment");
    }

    #[test]
    fn a_position_independent_image_is_placed_the_same_way_at_any_aligned_base() {
        let mut image = elf(KERNEL_BASE + 0x40, &[(KERNEL_BASE, 0x80, 0x80)]);
        image[16..18].copy_from_slice(&3u16.to_le_bytes());
        let (entry, copies) = plan(&image).unwrap();
        assert_eq!(entry - KERNEL_BASE, 0x40, "the entry, relative to the base");
        assert_eq!(copies[0].unwrap().at, 0);
        // Wherever the firmware's pages start, the kernel gets a megapage-aligned range inside the allocation.
        for at in [0x8f40_1000, 0x1_0200_0000, 0x1_0210_0000] {
            let base = aligned_base(at).unwrap();
            assert_eq!(base % KERNEL_ALIGN, 0);
            assert!(base >= at && base + KERNEL_SIZE <= at + KERNEL_SIZE + KERNEL_ALIGN);
        }
        assert_eq!(aligned_base(u64::MAX), None);
    }

    #[test]
    fn what_isnt_free_after_exit_is_handed_to_the_kernel_merged() {
        let map = [
            (7, 0x8000_0000, 0x200),     // conventional: free
            (6, 0x8020_0000, 0x10),      // runtime services data
            (5, 0x8021_0000, 0x10),      // runtime services code, adjacent: merged
            (4, 0x8022_0000, 0x100),     // boot services data: free after exit
            (0, 0x8f00_0000, 0x1),       // reserved
            (2, 0x8f00_1000, 0x10),      // the loader's own: free
            (11, 0x1000_0000, 0x1),      // MMIO
        ];
        let mut out = [(0, 0); 8];
        let n = reserved_ranges(map.into_iter(), &mut out).unwrap();
        assert_eq!(&out[..n], &[(0x8020_0000, 0x20000), (0x8f00_0000, 0x1000), (0x1000_0000, 0x1000)]);
        let mut tiny = [(0, 0); 1];
        assert_eq!(reserved_ranges(map.into_iter(), &mut tiny), None, "never truncated");
        assert_eq!(HANDOFF_MAGIC.to_le_bytes(), *b"LNTNEFI1");
    }

    #[test]
    fn a_device_tree_copy_is_bounded_by_its_header() {
        assert_eq!(device_tree_size([0xd0, 0x0d, 0xfe, 0xed, 0, 0, 0x13, 0xa4]), Some(0x13a4));
        assert_eq!(device_tree_size([0xd0, 0x0d, 0xfe, 0xee, 0, 0, 0x13, 0xa4]), None, "not a tree");
        assert_eq!(device_tree_size([0xd0, 0x0d, 0xfe, 0xed, 0, 0, 0, 8]), None, "shorter than its header");
        assert_eq!(device_tree_size([0xd0, 0x0d, 0xfe, 0xed, 0, 0x10, 0, 1]), None, "too big");
    }

    #[test]
    fn the_kernel_goes_in_the_lowest_free_run_that_fits() {
        let mega = KERNEL_ALIGN;
        // QEMU under EDK2: a run too short once aligned, the one it fits, and a higher one.
        let free = [(0x8f00_0000, 0x40_0000), (0x8020_1000, 4 * mega), (0x8000_0000, mega), (0x8100_0000, 32 * mega)];
        assert_eq!(lowest_fit(free.into_iter()), Some(0x8040_0000), "aligned up inside the second run");
        // The K3's RAM, above 4 GiB.
        assert_eq!(lowest_fit([(0x1_0200_0000, 1 << 30)].into_iter()), Some(0x1_0200_0000));
        assert_eq!(lowest_fit([(0x8000_0000, KERNEL_SIZE - 1)].into_iter()), None);
        assert_eq!(lowest_fit([(u64::MAX - 10, 100)].into_iter()), None, "no overflow");
    }

    #[test]
    fn anything_outside_the_kernels_range_or_the_file_is_refused() {
        assert_eq!(plan(&elf(0x8000_0000, &[(0x8000_0000, 4, 4)])).err(), Some(Refused::OutOfRange), "OpenSBI's");
        let end = KERNEL_BASE + KERNEL_SIZE;
        assert_eq!(plan(&elf(end - 4, &[(end - 4, 4, 8)])).err(), Some(Refused::OutOfRange), "past the end");
        assert_eq!(plan(&elf(KERNEL_BASE, &[(KERNEL_BASE, 8, 4)])).err(), Some(Refused::OutOfRange), "filesz > memsz");
        let mut short = elf(KERNEL_BASE, &[(KERNEL_BASE, 64, 64)]);
        short.truncate(short.len() - 1);
        assert_eq!(plan(&short).err(), Some(Refused::OutOfRange), "bytes past the file");
        assert_eq!(plan(&elf(KERNEL_BASE + 0x9000, &[(KERNEL_BASE, 4, 4)])).err(), Some(Refused::BadEntry));
        assert_eq!(plan(b"MZ not an elf").err(), Some(Refused::NotRiscvElf));
        let mut wrong_machine = elf(KERNEL_BASE, &[(KERNEL_BASE, 4, 4)]);
        wrong_machine[18] = 62;
        assert_eq!(plan(&wrong_machine).err(), Some(Refused::NotRiscvElf));
    }
}
