//! The EFI loader's decision ([RFC-0032](../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)): where each part of
//! the boot image goes, and whether it may go there at all, with no firmware calls in it, so it can be tested on a host.
//! `src/main.rs` is the UEFI program around it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Where the kernel runs: 2 MiB above the start of QEMU `virt`'s RAM, where OpenSBI's jump firmware puts it, through its
/// two reserved megapages (`lantern-boot/linker.ld`).
pub const KERNEL_BASE: u64 = 0x8020_0000;
pub const KERNEL_SIZE: u64 = 4 << 20;

/// One part of the boot image to copy: the file's bytes `[offset, offset + filesz)` to `KERNEL_BASE + at`, then zeros to
/// `memsz`.
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

/// The boot image's entry point and its copies, all checked to land inside the kernel's range and to come from inside
/// `elf`.
pub fn plan(elf: &[u8]) -> Result<(u64, [Option<Copy>; MAX_SEGMENTS]), Refused> {
    let ok = elf.get(..4) == Some(b"\x7fELF") && elf.get(4) == Some(&2) && elf.get(5) == Some(&1);
    if !ok || u16_at(elf, 16) != Some(2) || u16_at(elf, 18) != Some(243) {
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
