//! A minimal, hand-written flattened-device-tree (FDT / DTB) reader — just
//! enough to find where RAM is.
//!
//! **Deliberately narrow, not a general-purpose FDT library**, the same
//! discipline [`crate::elf`] follows (RFC-0008/ADR-0012's TCB-impact reasoning:
//! ~150 lines of from-scratch, bounds-checked parsing over a general-purpose
//! dependency this crate would use 2% of). It validates the header, walks the
//! structure block once, reads `#address-cells` / `#size-cells` from the root
//! node, finds the first `/memory` node, and returns the first `(base, size)`
//! pair from its `reg` property. Everything else in the tree is skipped;
//! anything malformed is an `Err`, never a permissive guess
//! (`lantern-boot/THREAT_MODEL.md`).
//!
//! OpenSBI (QEMU's `-bios default`) passes the DTB pointer in `a1` to
//! [`_start`](../entry.rs); Phase 1 ignored it and hardcoded QEMU `virt`'s RAM
//! layout in [`crate::pmm`]. This module replaces that guess with the real
//! range so the loader's memory-backed `Untyped` is sized to the machine it
//! actually booted on.

// `ram_region` / `total_size` are the `riscv64` boot entry points; the portable
// `parse_ram_region` is what the host tests exercise. Mirrors `elf.rs`.
#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FdtError {
    TooShortForHeader,
    BadMagic,
    UnsupportedVersion(u32),
    StructBlockOutOfBounds,
    StringsBlockOutOfBounds,
    /// The structure block ended (or a token/string ran past its bounds) before
    /// a `/memory` node with a usable `reg` was found.
    Truncated,
    NoMemoryNode,
    /// `reg` present but too short for one `(address, size)` pair at the root's
    /// declared cell counts, or a cell count this reader doesn't support.
    BadMemoryReg,
}

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

/// DT spec defaults when the root node omits them. QEMU `virt` sets both to 2,
/// but honour whatever the tree declares.
const DEFAULT_ADDRESS_CELLS: u32 = 2;
const DEFAULT_SIZE_CELLS: u32 = 1;

fn be32(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Total size of the blob, from its header — so a caller with only a pointer can
/// build a correctly-bounded slice before calling [`parse_ram_region`].
///
/// # Safety
/// `dtb` must point at readable memory holding at least an FDT header
/// (8 bytes suffice for this call).
pub unsafe fn total_size(dtb: *const u8) -> Result<usize, FdtError> {
    // SAFETY: forwarded to this function's contract.
    let header = unsafe { core::slice::from_raw_parts(dtb, 8) };
    if be32(header, 0) != Some(FDT_MAGIC) {
        return Err(FdtError::BadMagic);
    }
    Ok(be32(header, 4).ok_or(FdtError::TooShortForHeader)? as usize)
}

/// Reads the whole DTB at `dtb` and returns `(ram_base, ram_size)` from its
/// first `/memory` node, or `None` on any malformed input — a caller that gets
/// `None` should fall back to a hardcoded range ([`crate::pmm`]).
///
/// # Safety
/// `dtb` must point at a readable, valid flattened device tree (as passed by
/// OpenSBI in `a1`).
pub unsafe fn ram_region(dtb: *const u8) -> Option<(u64, u64)> {
    // SAFETY: forwarded to this function's contract.
    let size = unsafe { total_size(dtb) }.ok()?;
    // SAFETY: `size` is the blob's own declared length; the contract says the
    // whole blob is readable.
    let bytes = unsafe { core::slice::from_raw_parts(dtb, size) };
    parse_ram_region(bytes).ok()
}

/// The pure, host-testable core: parse `fdt` and return `(ram_base, ram_size)`.
pub fn parse_ram_region(fdt: &[u8]) -> Result<(u64, u64), FdtError> {
    if fdt.len() < 40 {
        return Err(FdtError::TooShortForHeader);
    }
    if be32(fdt, 0) != Some(FDT_MAGIC) {
        return Err(FdtError::BadMagic);
    }
    let version = be32(fdt, 20).unwrap();
    // v16 introduced the current structure-block layout; every DTB QEMU/OpenSBI
    // produces is v17. Reject older layouts rather than misread them.
    if version < 16 {
        return Err(FdtError::UnsupportedVersion(version));
    }
    let off_struct = be32(fdt, 8).unwrap() as usize;
    let off_strings = be32(fdt, 12).unwrap() as usize;
    let size_struct = be32(fdt, 36).unwrap() as usize;

    let struct_end = off_struct.checked_add(size_struct).ok_or(FdtError::StructBlockOutOfBounds)?;
    if struct_end > fdt.len() || off_strings > fdt.len() {
        return Err(FdtError::StructBlockOutOfBounds);
    }
    let strings = &fdt[off_strings..];

    // Walk the structure block. Track nesting depth so we can tell the root
    // node's own properties from a child's, and recognise a `/memory` node as a
    // direct child of root (depth 1).
    let mut cursor = off_struct;
    let mut depth: i32 = 0;
    let mut addr_cells = DEFAULT_ADDRESS_CELLS;
    let mut size_cells = DEFAULT_SIZE_CELLS;
    let mut in_memory_node = false;

    loop {
        let token = be32(fdt, cursor).ok_or(FdtError::Truncated)?;
        cursor += 4;
        match token {
            FDT_BEGIN_NODE => {
                let name_start = cursor;
                let name_end = fdt[name_start..struct_end]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| name_start + p)
                    .ok_or(FdtError::Truncated)?;
                let name = &fdt[name_start..name_end];
                cursor = align4(name_end + 1);
                depth += 1;
                // "memory" or "memory@<addr>", directly under root.
                in_memory_node = depth == 2
                    && (name == b"memory" || name.starts_with(b"memory@"));
            }
            FDT_END_NODE => {
                depth -= 1;
                in_memory_node = false;
                if depth == 0 {
                    return Err(FdtError::NoMemoryNode);
                }
            }
            FDT_PROP => {
                let len = be32(fdt, cursor).ok_or(FdtError::Truncated)? as usize;
                let nameoff = be32(fdt, cursor + 4).ok_or(FdtError::Truncated)? as usize;
                let val_start = cursor + 8;
                let val_end = val_start.checked_add(len).ok_or(FdtError::Truncated)?;
                if val_end > struct_end {
                    return Err(FdtError::Truncated);
                }
                let value = &fdt[val_start..val_end];
                let pname = strings
                    .get(nameoff..)
                    .and_then(|s| s.iter().position(|&b| b == 0).map(|p| &s[..p]))
                    .ok_or(FdtError::StringsBlockOutOfBounds)?;

                if depth == 1 {
                    // Root node's cell counts.
                    match pname {
                        b"#address-cells" if value.len() == 4 => {
                            addr_cells = u32::from_be_bytes(value.try_into().unwrap());
                        }
                        b"#size-cells" if value.len() == 4 => {
                            size_cells = u32::from_be_bytes(value.try_into().unwrap());
                        }
                        _ => {}
                    }
                } else if in_memory_node && pname == b"reg" {
                    return read_reg(value, addr_cells, size_cells);
                }
                cursor = align4(val_end);
            }
            FDT_NOP => {}
            FDT_END => return Err(FdtError::NoMemoryNode),
            _ => return Err(FdtError::Truncated),
        }
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// The first `(address, size)` pair from a `reg` value, each field `cells` * 4
/// bytes, big-endian. This reader supports 1- or 2-cell fields (32- or 64-bit),
/// which covers every real riscv64 machine.
fn read_reg(value: &[u8], addr_cells: u32, size_cells: u32) -> Result<(u64, u64), FdtError> {
    if !(1..=2).contains(&addr_cells) || !(1..=2).contains(&size_cells) {
        return Err(FdtError::BadMemoryReg);
    }
    let addr_bytes = addr_cells as usize * 4;
    let size_bytes = size_cells as usize * 4;
    if value.len() < addr_bytes + size_bytes {
        return Err(FdtError::BadMemoryReg);
    }
    let base = read_cells(&value[..addr_bytes]);
    let size = read_cells(&value[addr_bytes..addr_bytes + size_bytes]);
    Ok((base, size))
}

fn read_cells(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal v17 DTB: root with `#address-cells`/`#size-cells`, one
    /// `memory@X` child with `reg`, plus a decoy sibling node and property.
    fn build_dtb(addr_cells: u32, size_cells: u32, reg: &[u8]) -> Vec<u8> {
        // Strings block: property names, null-terminated.
        let mut strings = Vec::new();
        let ac_off = strings.len() as u32;
        strings.extend_from_slice(b"#address-cells\0");
        let sc_off = strings.len() as u32;
        strings.extend_from_slice(b"#size-cells\0");
        let dt_off = strings.len() as u32;
        strings.extend_from_slice(b"device_type\0");
        let reg_off = strings.len() as u32;
        strings.extend_from_slice(b"reg\0");

        let mut st = Vec::new();
        let tok = |st: &mut Vec<u8>, t: u32| st.extend_from_slice(&t.to_be_bytes());
        let prop = |st: &mut Vec<u8>, nameoff: u32, val: &[u8]| {
            st.extend_from_slice(&FDT_PROP.to_be_bytes());
            st.extend_from_slice(&(val.len() as u32).to_be_bytes());
            st.extend_from_slice(&nameoff.to_be_bytes());
            st.extend_from_slice(val);
            while !st.len().is_multiple_of(4) {
                st.push(0);
            }
        };
        let node = |st: &mut Vec<u8>, name: &[u8]| {
            st.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            st.extend_from_slice(name);
            st.push(0);
            while !st.len().is_multiple_of(4) {
                st.push(0);
            }
        };

        node(&mut st, b""); // root
        prop(&mut st, ac_off, &addr_cells.to_be_bytes());
        prop(&mut st, sc_off, &size_cells.to_be_bytes());
        node(&mut st, b"chosen"); // decoy sibling, no reg
        prop(&mut st, dt_off, b"whatever\0");
        tok(&mut st, FDT_END_NODE);
        node(&mut st, b"memory@80000000");
        prop(&mut st, dt_off, b"memory\0");
        prop(&mut st, reg_off, reg);
        tok(&mut st, FDT_END_NODE);
        tok(&mut st, FDT_END_NODE); // close root
        tok(&mut st, FDT_END);

        let header_len = 40;
        let off_struct = header_len;
        let off_strings = off_struct + st.len();
        let total = off_strings + strings.len();

        let mut dtb = Vec::new();
        let h = |dtb: &mut Vec<u8>, v: u32| dtb.extend_from_slice(&v.to_be_bytes());
        h(&mut dtb, FDT_MAGIC);
        h(&mut dtb, total as u32);
        h(&mut dtb, off_struct as u32);
        h(&mut dtb, off_strings as u32);
        h(&mut dtb, 0); // off_mem_rsvmap
        h(&mut dtb, 17); // version
        h(&mut dtb, 16); // last_comp_version
        h(&mut dtb, 0); // boot_cpuid_phys
        h(&mut dtb, strings.len() as u32);
        h(&mut dtb, st.len() as u32);
        dtb.extend_from_slice(&st);
        dtb.extend_from_slice(&strings);
        dtb
    }

    #[test]
    fn reads_qemu_virt_style_2_2_cells() {
        // reg = <0x0 0x80000000 0x0 0x08000000> — 128 MiB at 0x8000_0000.
        let reg = [0u8, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x08, 0, 0, 0];
        let dtb = build_dtb(2, 2, &reg);
        assert_eq!(parse_ram_region(&dtb), Ok((0x8000_0000, 0x0800_0000)));
    }

    #[test]
    fn reads_1_1_cells() {
        let reg = [0x80u8, 0, 0, 0, 0x04, 0, 0, 0]; // 64 MiB at 0x8000_0000
        let dtb = build_dtb(1, 1, &reg);
        assert_eq!(parse_ram_region(&dtb), Ok((0x8000_0000, 0x0400_0000)));
    }

    #[test]
    fn full_64_bit_base_and_size() {
        let reg = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // base = 0x1_0000_0000
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // size = 0x2_0000_0000
        ];
        let dtb = build_dtb(2, 2, &reg);
        assert_eq!(parse_ram_region(&dtb), Ok((0x1_0000_0000, 0x2_0000_0000)));
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        let mut dtb = build_dtb(2, 2, &[0; 16]);
        dtb[0] ^= 0xFF;
        assert_eq!(parse_ram_region(&dtb), Err(FdtError::BadMagic));

        let dtb = build_dtb(2, 2, &[0; 16]);
        assert_eq!(parse_ram_region(&dtb[..30]), Err(FdtError::TooShortForHeader));
        // Cut into the struct block: the walk runs off the end.
        assert!(parse_ram_region(&dtb[..dtb.len() - 20]).is_err());
    }

    #[test]
    fn no_memory_node_is_an_error_not_a_guess() {
        // A reg too short for the declared cells.
        let dtb = build_dtb(2, 2, &[0, 0, 0, 0]);
        assert_eq!(parse_ram_region(&dtb), Err(FdtError::BadMemoryReg));
    }

    #[test]
    fn total_size_matches_the_header() {
        let dtb = build_dtb(2, 2, &[0; 16]);
        // SAFETY: `dtb` is a live, valid FDT blob for the duration of this call.
        assert_eq!(unsafe { total_size(dtb.as_ptr()) }, Ok(dtb.len()));
    }
}
