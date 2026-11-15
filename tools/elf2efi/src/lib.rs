//! ELF to PE/COFF, for [RFC-0032](../../../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)'s EFI loader.
//!
//! The input is a position-independent riscv64 ELF linked at a base of [`IMAGE_START`] or above, whose only dynamic
//! relocations are `R_RISCV_RELATIVE`. The output is a PE32+ EFI application with an image base of 0, so an address in
//! the ELF is the same address in the PE image, relative to wherever the firmware loads it:
//!
//! - each `PT_LOAD` segment is a section, with that segment's permissions;
//! - each `R_RISCV_RELATIVE` is a `DIR64` base relocation, with its addend written in place, which is where PE keeps it;
//! - the entry point is the ELF's.
//!
//! Anything else (another relocation type, overlapping segments, one below the headers) is refused.

pub const IMAGE_START: u64 = 0x1000;
const SECTION_ALIGN: u64 = 0x1000;
const FILE_ALIGN: u64 = 0x200;
const MACHINE_RISCV64: u16 = 0x5064;
const SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const R_RISCV_RELATIVE: u32 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub data: Vec<u8>,
    pub flags: u32,
}

/// What the PE needs from the ELF.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    pub entry: u64,
    pub segments: Vec<Segment>,
    /// Each relocation's address, whose 8 bytes hold the address it refers to (base 0) once [`Image::apply`] has run.
    pub relocations: Vec<u64>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(b.get(at..at + 2).ok_or("truncated")?.try_into().unwrap()))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(b.get(at..at + 4).ok_or("truncated")?.try_into().unwrap()))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(b.get(at..at + 8).ok_or("truncated")?.try_into().unwrap()))
}

/// Reads the loadable segments and relocations of a riscv64 PIE.
pub fn read_elf(elf: &[u8]) -> Result<Image, String> {
    if elf.get(..4) != Some(b"\x7fELF") || elf.get(4) != Some(&2) || elf.get(5) != Some(&1) {
        return Err("not a 64-bit little-endian ELF".into());
    }
    if u16_at(elf, 18)? != 243 {
        return Err("not RISC-V".into());
    }
    if u16_at(elf, 16)? != 3 {
        return Err("not position-independent (ET_DYN)".into());
    }
    let entry = u64_at(elf, 24)?;
    let (phoff, phentsize, phnum) = (u64_at(elf, 32)? as usize, u16_at(elf, 54)? as usize, u16_at(elf, 56)? as usize);
    let mut segments: Vec<Segment> = Vec::new();
    let mut dynamic = None;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let (kind, flags) = (u32_at(elf, ph)?, u32_at(elf, ph + 4)?);
        let (offset, vaddr, filesz, memsz) = (u64_at(elf, ph + 8)?, u64_at(elf, ph + 16)?, u64_at(elf, ph + 32)?, u64_at(elf, ph + 40)?);
        match kind {
            PT_LOAD if memsz > 0 => {
                if vaddr < IMAGE_START || vaddr % SECTION_ALIGN != 0 || filesz > memsz {
                    return Err(format!("segment at {vaddr:#x} must be page-aligned, from {IMAGE_START:#x}"));
                }
                let data = elf.get(offset as usize..(offset + filesz) as usize).ok_or("segment past the file")?.to_vec();
                if segments.last().is_some_and(|s| align(s.vaddr + s.memsz, SECTION_ALIGN) > vaddr) {
                    return Err("segments overlap, or aren't in order".into());
                }
                segments.push(Segment { vaddr, memsz, data, flags });
            }
            PT_DYNAMIC => dynamic = Some((offset as usize, filesz as usize)),
            _ => {}
        }
    }
    if segments.is_empty() {
        return Err("nothing to load".into());
    }
    let mut relocations = Vec::new();
    let mut image = Image { entry, segments, relocations: Vec::new() };
    if let Some((offset, size)) = dynamic {
        let (mut rela, mut relasz, mut relaent) = (0, 0, 24);
        for at in (offset..offset + size).step_by(16) {
            match u64_at(elf, at)? {
                DT_NULL => break,
                DT_RELA => rela = u64_at(elf, at + 8)?,
                DT_RELASZ => relasz = u64_at(elf, at + 8)?,
                DT_RELAENT => relaent = u64_at(elf, at + 8)?,
                _ => {}
            }
        }
        if relaent != 24 {
            return Err("unexpected relocation entry size".into());
        }
        for i in 0..relasz / 24 {
            let at = image.file_offset_of(elf, rela + i * 24)?;
            let (r_offset, info, addend) = (u64_at(elf, at)?, u64_at(elf, at + 8)?, u64_at(elf, at + 16)?);
            if info as u32 != R_RISCV_RELATIVE {
                return Err(format!("relocation type {} at {r_offset:#x}: only R_RISCV_RELATIVE is supported", info as u32));
            }
            image.put(r_offset, addend)?;
            relocations.push(r_offset);
        }
    }
    relocations.sort_unstable();
    image.relocations = relocations;
    Ok(image)
}

fn align(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

impl Image {
    /// Where in the ELF file the bytes at `vaddr` are: the relocation table lives in a loaded segment.
    fn file_offset_of(&self, elf: &[u8], vaddr: u64) -> Result<usize, String> {
        let phoff = u64_at(elf, 32)? as usize;
        let (phentsize, phnum) = (u16_at(elf, 54)? as usize, u16_at(elf, 56)? as usize);
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            let (offset, start, filesz) = (u64_at(elf, ph + 8)?, u64_at(elf, ph + 16)?, u64_at(elf, ph + 32)?);
            if u32_at(elf, ph)? == PT_LOAD && (start..start + filesz).contains(&vaddr) {
                return Ok((offset + vaddr - start) as usize);
            }
        }
        Err(format!("{vaddr:#x} isn't in the file"))
    }

    /// Writes `value` at `vaddr`, which must be inside a segment's file bytes.
    fn put(&mut self, vaddr: u64, value: u64) -> Result<(), String> {
        let segment = self
            .segments
            .iter_mut()
            .find(|s| (s.vaddr..s.vaddr + s.data.len() as u64).contains(&vaddr) && vaddr + 8 <= s.vaddr + s.data.len() as u64)
            .ok_or_else(|| format!("relocation at {vaddr:#x} isn't in a segment's file bytes"))?;
        let at = (vaddr - segment.vaddr) as usize;
        segment.data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

/// The `.reloc` section's bytes: one block per 4 KiB page holding relocations, each block padded to 4 bytes.
pub fn base_relocations(relocations: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < relocations.len() {
        let page = relocations[i] & !0xfff;
        let entries: Vec<u16> = relocations[i..]
            .iter()
            .take_while(|&&r| r & !0xfff == page)
            .map(|&r| IMAGE_REL_BASED_DIR64 << 12 | (r & 0xfff) as u16)
            .collect();
        i += entries.len();
        let padded = entries.len() + entries.len() % 2;
        out.extend_from_slice(&(page as u32).to_le_bytes());
        out.extend_from_slice(&((8 + padded * 2) as u32).to_le_bytes());
        for e in &entries {
            out.extend_from_slice(&e.to_le_bytes());
        }
        if padded > entries.len() {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
    }
    out
}

/// The PE32+ EFI application for `image`.
pub fn write_pe(image: &Image) -> Vec<u8> {
    let reloc = base_relocations(&image.relocations);
    let end = image.segments.iter().map(|s| align(s.vaddr + s.memsz, SECTION_ALIGN)).max().unwrap();
    let reloc_rva = end;
    let size_of_image = align(reloc_rva + reloc.len().max(1) as u64, SECTION_ALIGN);
    let sections = image.segments.len() + 1;
    let headers_len = 0x40 + 4 + 20 + 240 + sections * 40;
    let size_of_headers = align(headers_len as u64, FILE_ALIGN);

    let mut raw: Vec<(u64, u64)> = Vec::new(); // (file offset, raw size) per section
    let mut at = size_of_headers;
    for s in &image.segments {
        let size = align(s.data.len() as u64, FILE_ALIGN);
        raw.push((at, size));
        at += size;
    }
    let reloc_raw = (at, align(reloc.len() as u64, FILE_ALIGN));
    let mut pe = vec![0u8; (reloc_raw.0 + reloc_raw.1) as usize];

    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    pe[coff..coff + 2].copy_from_slice(&MACHINE_RISCV64.to_le_bytes());
    pe[coff + 2..coff + 4].copy_from_slice(&(sections as u16).to_le_bytes());
    pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE.
    pe[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt = coff + 20;
    let code: u64 = image.segments.iter().filter(|s| s.flags & PF_X != 0).map(|s| align(s.memsz, FILE_ALIGN)).sum();
    let data: u64 = image.segments.iter().filter(|s| s.flags & PF_X == 0).map(|s| align(s.memsz, FILE_ALIGN)).sum();
    let base_of_code = image.segments.iter().find(|s| s.flags & PF_X != 0).map_or(IMAGE_START, |s| s.vaddr);
    let w16 = |pe: &mut Vec<u8>, at: usize, v: u16| pe[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let w32 = |pe: &mut Vec<u8>, at: usize, v: u32| pe[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let w64 = |pe: &mut Vec<u8>, at: usize, v: u64| pe[at..at + 8].copy_from_slice(&v.to_le_bytes());
    w16(&mut pe, opt, 0x20b);
    w32(&mut pe, opt + 4, code as u32);
    w32(&mut pe, opt + 8, data as u32);
    w32(&mut pe, opt + 16, image.entry as u32);
    w32(&mut pe, opt + 20, base_of_code as u32);
    w64(&mut pe, opt + 24, 0); // ImageBase: addresses in the image are relative to wherever it's loaded.
    w32(&mut pe, opt + 32, SECTION_ALIGN as u32);
    w32(&mut pe, opt + 36, FILE_ALIGN as u32);
    w16(&mut pe, opt + 48, 1); // Subsystem version 1.0.
    w32(&mut pe, opt + 56, size_of_image as u32);
    w32(&mut pe, opt + 60, size_of_headers as u32);
    w16(&mut pe, opt + 68, SUBSYSTEM_EFI_APPLICATION);
    w64(&mut pe, opt + 72, 0x10000); // Stack and heap sizes: UEFI ignores them.
    w64(&mut pe, opt + 80, 0x10000);
    w64(&mut pe, opt + 88, 0x10000);
    w64(&mut pe, opt + 96, 0x10000);
    w32(&mut pe, opt + 108, 16);
    // Data directory 5: the base relocation table.
    w32(&mut pe, opt + 112 + 5 * 8, reloc_rva as u32);
    w32(&mut pe, opt + 112 + 5 * 8 + 4, reloc.len() as u32);

    let mut section = opt + 240;
    let mut header = |pe: &mut Vec<u8>, name: &[u8], vsize: u64, rva: u64, raw: (u64, u64), characteristics: u32| {
        pe[section..section + name.len()].copy_from_slice(name);
        w32(pe, section + 8, vsize as u32);
        w32(pe, section + 12, rva as u32);
        w32(pe, section + 16, raw.1 as u32);
        w32(pe, section + 20, raw.0 as u32);
        w32(pe, section + 36, characteristics);
        section += 40;
    };
    for (s, &raw) in image.segments.iter().zip(&raw) {
        let (name, mut characteristics): (&[u8], u32) = if s.flags & PF_X != 0 {
            (b".text", 0x0000_0020) // CNT_CODE
        } else if s.flags & PF_W != 0 {
            (b".data", 0x0000_0040) // CNT_INITIALIZED_DATA
        } else {
            (b".rdata", 0x0000_0040)
        };
        for (flag, bit) in [(PF_X, 0x2000_0000u32), (PF_R, 0x4000_0000), (PF_W, 0x8000_0000)] {
            if s.flags & flag != 0 {
                characteristics |= bit;
            }
        }
        header(&mut pe, name, s.memsz, s.vaddr, raw, characteristics);
        pe[raw.0 as usize..raw.0 as usize + s.data.len()].copy_from_slice(&s.data);
    }
    // INITIALIZED_DATA | DISCARDABLE | READ.
    header(&mut pe, b".reloc", reloc.len() as u64, reloc_rva, reloc_raw, 0x4200_0040);
    pe[reloc_raw.0 as usize..reloc_raw.0 as usize + reloc.len()].copy_from_slice(&reloc);
    pe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relocations_group_by_page_and_pad_to_four_bytes() {
        let blocks = base_relocations(&[0x1008, 0x1010, 0x1ff8, 0x3000]);
        // Page 0x1000: three entries, padded to four; page 0x3000: one, padded to two.
        assert_eq!(u32::from_le_bytes(blocks[0..4].try_into().unwrap()), 0x1000);
        assert_eq!(u32::from_le_bytes(blocks[4..8].try_into().unwrap()), 8 + 4 * 2);
        assert_eq!(u16::from_le_bytes(blocks[8..10].try_into().unwrap()), 0xa008);
        assert_eq!(u16::from_le_bytes(blocks[12..14].try_into().unwrap()), 0xaff8);
        assert_eq!(u16::from_le_bytes(blocks[14..16].try_into().unwrap()), 0, "padding");
        assert_eq!(u32::from_le_bytes(blocks[16..20].try_into().unwrap()), 0x3000);
        assert_eq!(u32::from_le_bytes(blocks[20..24].try_into().unwrap()), 8 + 2 * 2);
        assert_eq!(blocks.len(), 28);
        assert!(base_relocations(&[]).is_empty());
    }

    fn image() -> Image {
        Image {
            entry: 0x1010,
            segments: vec![
                Segment { vaddr: 0x1000, memsz: 0x30, data: vec![0x13; 0x30], flags: PF_R | PF_X },
                Segment { vaddr: 0x2000, memsz: 0x2000, data: vec![0; 0x10], flags: PF_R | PF_W },
            ],
            relocations: vec![0x2008],
        }
    }

    #[test]
    fn a_pe_has_its_headers_sections_and_relocations_where_uefi_looks() {
        let pe = write_pe(&image());
        assert_eq!(&pe[0..2], b"MZ");
        assert_eq!(&pe[0x40..0x44], b"PE\0\0");
        assert_eq!(u16::from_le_bytes(pe[0x44..0x46].try_into().unwrap()), MACHINE_RISCV64);
        assert_eq!(u16::from_le_bytes(pe[0x46..0x48].try_into().unwrap()), 3, "two segments and .reloc");
        let opt = 0x44 + 20;
        assert_eq!(u16::from_le_bytes(pe[opt..opt + 2].try_into().unwrap()), 0x20b);
        assert_eq!(u32::from_le_bytes(pe[opt + 16..opt + 20].try_into().unwrap()), 0x1010, "entry");
        assert_eq!(u16::from_le_bytes(pe[opt + 68..opt + 70].try_into().unwrap()), SUBSYSTEM_EFI_APPLICATION);
        assert_eq!(u32::from_le_bytes(pe[opt + 56..opt + 60].try_into().unwrap()), 0x5000, "SizeOfImage");
        assert_eq!(u32::from_le_bytes(pe[opt + 152..opt + 156].try_into().unwrap()), 0x4000, "relocations after the data");
        // The first section's bytes are where its header says.
        let section = opt + 240;
        let raw = u32::from_le_bytes(pe[section + 20..section + 24].try_into().unwrap()) as usize;
        assert_eq!(&pe[raw..raw + 0x30], &[0x13; 0x30]);
        assert_eq!(pe.len() % FILE_ALIGN as usize, 0);
    }
}
