//! A minimal, hand-written ELF64 parser — [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md).
//!
//! **Deliberately narrow, not a general-purpose ELF library.** Validates the
//! header (magic, 64-bit, little-endian, `EM_RISCV`, `ET_EXEC`), then only ever
//! looks at `PT_LOAD` program headers — the only thing `loader.rs` needs to
//! actually place a statically linked, position-dependent, no-libc binary into
//! memory. Every other segment type is either explicitly recognized as
//! harmless-to-skip (`PT_NULL`, `PT_PHDR`, `PT_GNU_STACK`, `PT_RISCV_ATTRIBUTES`
//! — all either empty or purely informational, produced by every normal
//! `rustc`/`lld` output, never actually loaded) or rejected outright
//! (`PT_DYNAMIC`, `PT_INTERP`, `PT_TLS`, anything unrecognized) — this loader
//! has no dynamic linker, no interpreter, no TLS support, and permissively
//! ignoring a segment type it doesn't understand is exactly the "parse
//! untrusted structure permissively" mistake `lantern-boot/THREAT_MODEL.md`
//! should not reintroduce (RFC-0008's "Threat model impact"). Every offset/size
//! read from the header is bounds-checked against the actual byte slice before
//! use — nothing here trusts a header field to be in-bounds.
//!
//! No external ELF-parsing crate: RFC-0008's "TCB impact" prefers ~150 lines of
//! narrowly scoped, from-scratch parsing over a general-purpose dependency this
//! project would use 5% of (ADR-0001's minimal-TCB-dependency preference).

#![allow(dead_code)] // Some fields (e.g. `ElfHeader::phentsize`) are read defensively but not all are load-bearing to `loader.rs` yet.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfError {
    TooShortForHeader,
    BadMagic,
    NotClass64,
    NotLittleEndian,
    NotRiscv,
    NotExecutable,
    ProgramHeaderOutOfBounds,
    SegmentOutOfBounds,
    UnsupportedSegmentType(u32),
}

const EI_CLASS_64: u8 = 2;
const EI_DATA_LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_RISCV: u16 = 0xF3;

const ELF_HEADER_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

/// Segment types `loader.rs` never loads but that carry no risk in silently
/// skipping — see the module doc.
const PT_NULL: u32 = 0;
const PT_PHDR: u32 = 6;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;

pub const PT_LOAD: u32 = 1;

pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
pub const PF_R: u32 = 1 << 2;

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}

#[derive(PartialEq, Eq, Debug)]
pub struct ElfHeader {
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
}

pub fn parse_header(bytes: &[u8]) -> Result<ElfHeader, ElfError> {
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(ElfError::TooShortForHeader);
    }
    if bytes[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(ElfError::BadMagic);
    }
    if bytes[4] != EI_CLASS_64 {
        return Err(ElfError::NotClass64);
    }
    if bytes[5] != EI_DATA_LSB {
        return Err(ElfError::NotLittleEndian);
    }
    let e_type = read_u16(bytes, 0x10).ok_or(ElfError::TooShortForHeader)?;
    if e_type != ET_EXEC {
        return Err(ElfError::NotExecutable);
    }
    let e_machine = read_u16(bytes, 0x12).ok_or(ElfError::TooShortForHeader)?;
    if e_machine != EM_RISCV {
        return Err(ElfError::NotRiscv);
    }
    let entry = read_u64(bytes, 0x18).ok_or(ElfError::TooShortForHeader)?;
    let phoff = read_u64(bytes, 0x20).ok_or(ElfError::TooShortForHeader)?;
    let phentsize = read_u16(bytes, 0x36).ok_or(ElfError::TooShortForHeader)?;
    let phnum = read_u16(bytes, 0x38).ok_or(ElfError::TooShortForHeader)?;
    Ok(ElfHeader { entry, phoff, phentsize, phnum })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProgramHeader {
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// Reads program header `index` (< `header.phnum`), returning `Ok(None)` for a
/// segment type `loader.rs` never needs to act on (see the module doc's
/// skip-list) or `Err` for anything else this minimal parser doesn't support.
pub fn program_header(
    bytes: &[u8],
    header: &ElfHeader,
    index: u16,
) -> Result<Option<ProgramHeader>, ElfError> {
    // `phentsize` is trusted only as a stride, not as a size to blindly read —
    // every field read below is independently bounds-checked regardless.
    let start = (header.phoff as usize)
        .checked_add(index as usize * header.phentsize as usize)
        .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    if start + PHDR_SIZE > bytes.len() {
        return Err(ElfError::ProgramHeaderOutOfBounds);
    }
    let p_type = read_u32(bytes, start).ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    match p_type {
        PT_LOAD => {}
        PT_NULL | PT_PHDR | PT_GNU_STACK | PT_RISCV_ATTRIBUTES => return Ok(None),
        other => return Err(ElfError::UnsupportedSegmentType(other)),
    }
    let flags = read_u32(bytes, start + 0x04).ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    let offset = read_u64(bytes, start + 0x08).ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    let vaddr = read_u64(bytes, start + 0x10).ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    let filesz = read_u64(bytes, start + 0x20).ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    let memsz = read_u64(bytes, start + 0x28).ok_or(ElfError::ProgramHeaderOutOfBounds)?;

    // The segment's own claimed file range must actually fit in `bytes` — a
    // segment whose `offset + filesz` overflows or runs past the end of the
    // image is rejected here, not left for `loader.rs` to discover via an
    // out-of-bounds slice (a panic, not a graceful load failure).
    let file_end = offset.checked_add(filesz).ok_or(ElfError::SegmentOutOfBounds)?;
    if file_end > bytes.len() as u64 || filesz > memsz {
        return Err(ElfError::SegmentOutOfBounds);
    }

    Ok(Some(ProgramHeader { flags, offset, vaddr, filesz, memsz }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header_bytes() -> [u8; ELF_HEADER_SIZE] {
        let mut b = [0u8; ELF_HEADER_SIZE];
        b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        b[4] = EI_CLASS_64;
        b[5] = EI_DATA_LSB;
        b[0x10..0x12].copy_from_slice(&ET_EXEC.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&EM_RISCV.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x8400_0000u64.to_le_bytes()); // entry
        b[0x20..0x28].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes()); // phoff
        b[0x36..0x38].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // phentsize
        b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // phnum
        b
    }

    #[test]
    fn parses_a_valid_header() {
        let bytes = valid_header_bytes();
        let header = parse_header(&bytes).unwrap();
        assert_eq!(header.entry, 0x8400_0000);
        assert_eq!(header.phoff, ELF_HEADER_SIZE as u64);
        assert_eq!(header.phnum, 1);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = valid_header_bytes();
        bytes[0] = 0;
        assert_eq!(parse_header(&bytes), Err(ElfError::BadMagic));
    }

    #[test]
    fn rejects_non_riscv() {
        let mut bytes = valid_header_bytes();
        bytes[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
        assert_eq!(parse_header(&bytes), Err(ElfError::NotRiscv));
    }

    #[test]
    fn rejects_a_too_short_buffer() {
        assert_eq!(parse_header(&[0u8; 10]), Err(ElfError::TooShortForHeader));
    }

    #[test]
    fn reads_a_pt_load_program_header() {
        let mut bytes = valid_header_bytes().to_vec();
        let mut phdr = [0u8; PHDR_SIZE];
        phdr[0x00..0x04].copy_from_slice(&PT_LOAD.to_le_bytes());
        phdr[0x04..0x08].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        phdr[0x08..0x10].copy_from_slice(&0u64.to_le_bytes()); // offset
        phdr[0x10..0x18].copy_from_slice(&0x8400_0000u64.to_le_bytes()); // vaddr
        phdr[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // filesz
        phdr[0x28..0x30].copy_from_slice(&64u64.to_le_bytes()); // memsz
        bytes.extend_from_slice(&phdr);
        bytes.resize(bytes.len().max(64), 0);

        let header = parse_header(&bytes).unwrap();
        let ph = program_header(&bytes, &header, 0).unwrap().unwrap();
        assert_eq!(ph.vaddr, 0x8400_0000);
        assert_eq!(ph.flags, PF_R | PF_X);
        assert_eq!(ph.filesz, 64);
    }

    #[test]
    fn skips_known_harmless_segment_types() {
        let mut bytes = valid_header_bytes().to_vec();
        let mut phdr = [0u8; PHDR_SIZE];
        phdr[0x00..0x04].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        bytes.extend_from_slice(&phdr);

        let header = parse_header(&bytes).unwrap();
        assert_eq!(program_header(&bytes, &header, 0).unwrap(), None);
    }

    #[test]
    fn rejects_an_unsupported_segment_type() {
        let mut bytes = valid_header_bytes().to_vec();
        let mut phdr = [0u8; PHDR_SIZE];
        const PT_DYNAMIC: u32 = 2;
        phdr[0x00..0x04].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        bytes.extend_from_slice(&phdr);

        let header = parse_header(&bytes).unwrap();
        assert_eq!(program_header(&bytes, &header, 0), Err(ElfError::UnsupportedSegmentType(PT_DYNAMIC)));
    }

    #[test]
    fn rejects_a_segment_claiming_bytes_past_the_end_of_the_image() {
        let mut bytes = valid_header_bytes().to_vec();
        let mut phdr = [0u8; PHDR_SIZE];
        phdr[0x00..0x04].copy_from_slice(&PT_LOAD.to_le_bytes());
        phdr[0x08..0x10].copy_from_slice(&0u64.to_le_bytes()); // offset
        phdr[0x20..0x28].copy_from_slice(&1_000_000u64.to_le_bytes()); // filesz -- way past EOF
        phdr[0x28..0x30].copy_from_slice(&1_000_000u64.to_le_bytes()); // memsz
        bytes.extend_from_slice(&phdr);

        let header = parse_header(&bytes).unwrap();
        assert_eq!(program_header(&bytes, &header, 0), Err(ElfError::SegmentOutOfBounds));
    }
}
