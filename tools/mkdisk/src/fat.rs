//! A FAT16 writer, for the EFI System Partition ([RFC-0032](../../../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)):
//! enough for a firmware to find `\EFI\BOOT\BOOTRISCV64.EFI` and the loader to find `\LANTERN\BOOT.ELF`.
//!
//! It writes a fresh volume, once: directories and files in contiguous clusters, two FATs, and a long-file-name entry
//! for any name that isn't 8.3. Nothing is ever deleted or rewritten. Timestamps are fixed, so the same files give the
//! same bytes.

const SECTOR: usize = 512;
const SECTORS_PER_CLUSTER: usize = 4;
const CLUSTER: usize = SECTOR * SECTORS_PER_CLUSTER;
const ROOT_ENTRIES: usize = 512;
const ENTRY: usize = 32;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0f;
/// 2026-11-14, 00:00, in FAT's packed date and time.
const DATE: u16 = (46 << 9) | (11 << 5) | 14;

enum Node {
    Dir(Vec<(String, Node)>),
    File(Vec<u8>),
}

/// The files to put on the volume, by path (`EFI/BOOT/BOOTRISCV64.EFI`).
#[derive(Default)]
pub struct Volume {
    root: Vec<(String, Node)>,
}

impl Volume {
    pub fn add(&mut self, path: &str, data: Vec<u8>) {
        let parts: Vec<&str> = path.split('/').collect();
        let (name, dirs) = parts.split_last().expect("a path");
        let mut at = &mut self.root;
        for dir in dirs {
            let i = match at.iter().position(|(n, _)| n == dir) {
                Some(i) => i,
                None => {
                    at.push((dir.to_string(), Node::Dir(Vec::new())));
                    at.len() - 1
                }
            };
            at = match &mut at[i].1 {
                Node::Dir(children) => children,
                Node::File(_) => panic!("{dir} is a file"),
            };
        }
        at.push((name.to_string(), Node::File(data)));
    }

    /// Writes the volume into `out`, a whole partition of `out.len() / 512` sectors starting at disk sector `first`.
    pub fn write(&self, out: &mut [u8], first: u64) -> Result<(), String> {
        let sectors = out.len() / SECTOR;
        let root_sectors = ROOT_ENTRIES * ENTRY / SECTOR;
        // Each FAT holds two bytes per cluster, plus the two reserved entries.
        let fat_sectors = (sectors / SECTORS_PER_CLUSTER * 2 + 4).div_ceil(SECTOR);
        let data_start = 1 + 2 * fat_sectors + root_sectors;
        let clusters = (sectors - data_start) / SECTORS_PER_CLUSTER;
        if !(4085..65525).contains(&clusters) {
            return Err(format!("{sectors} sectors is the wrong size for FAT16"));
        }
        out.fill(0);
        boot_sector(&mut out[..SECTOR], sectors, fat_sectors, first);

        let mut fat = vec![0u16; clusters + 2];
        fat[0] = 0xfff8;
        fat[1] = 0xffff;
        let mut next = 2usize;
        let mut root = Vec::new();
        for (name, node) in &self.root {
            write_node(out, data_start, &mut fat, &mut next, clusters, name, node, 0, &mut root)?;
        }
        if root.len() > ROOT_ENTRIES * ENTRY {
            return Err("too many entries in the root".into());
        }
        let root_at = (1 + 2 * fat_sectors) * SECTOR;
        out[root_at..root_at + root.len()].copy_from_slice(&root);
        for copy in 0..2 {
            let at = (1 + copy * fat_sectors) * SECTOR;
            for (i, e) in fat.iter().enumerate() {
                out[at + i * 2..at + i * 2 + 2].copy_from_slice(&e.to_le_bytes());
            }
        }
        Ok(())
    }
}

fn boot_sector(b: &mut [u8], sectors: usize, fat_sectors: usize, hidden: u64) {
    b[0..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    b[3..11].copy_from_slice(b"LANTERN ");
    b[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    b[13] = SECTORS_PER_CLUSTER as u8;
    b[14..16].copy_from_slice(&1u16.to_le_bytes());
    b[16] = 2;
    b[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    if sectors < 0x10000 {
        b[19..21].copy_from_slice(&(sectors as u16).to_le_bytes());
    } else {
        b[32..36].copy_from_slice(&(sectors as u32).to_le_bytes());
    }
    b[21] = 0xf8;
    b[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    b[24..26].copy_from_slice(&63u16.to_le_bytes());
    b[26..28].copy_from_slice(&255u16.to_le_bytes());
    b[28..32].copy_from_slice(&(hidden as u32).to_le_bytes());
    b[36] = 0x80;
    b[38] = 0x29;
    b[39..43].copy_from_slice(&0x4c4e_5452u32.to_le_bytes());
    b[43..54].copy_from_slice(b"NO NAME    ");
    b[54..62].copy_from_slice(b"FAT16   ");
    b[510] = 0x55;
    b[511] = 0xaa;
}

/// Writes `node` into fresh clusters from `next`, and appends its directory entries to `parent`.
#[allow(clippy::too_many_arguments)]
fn write_node(
    out: &mut [u8],
    data_start: usize,
    fat: &mut [u16],
    next: &mut usize,
    clusters: usize,
    name: &str,
    node: &Node,
    parent_cluster: u16,
    parent: &mut Vec<u8>,
) -> Result<(), String> {
    let at = |cluster: u16| (data_start + (cluster as usize - 2) * SECTORS_PER_CLUSTER) * SECTOR;
    match node {
        Node::File(data) => {
            let cluster = if data.is_empty() { 0 } else { alloc(next, clusters, fat, data.len())? };
            if cluster != 0 {
                out[at(cluster)..at(cluster) + data.len()].copy_from_slice(data);
            }
            entries(parent, name, ATTR_ARCHIVE, cluster, data.len() as u32);
        }
        Node::Dir(children) => {
            // Its entries first, to know its size; then its clusters.
            let mut own = Vec::new();
            let mut nested = Vec::new();
            let cluster_guess = *next as u16;
            entry(&mut own, *b".          ", ATTR_DIRECTORY, cluster_guess, 0);
            entry(&mut own, *b"..         ", ATTR_DIRECTORY, parent_cluster, 0);
            // Reserve the directory's own clusters before its children's: count its entries first.
            let count: usize = 2 + children.iter().map(|(n, _)| 1 + lfn_count(n)).sum::<usize>();
            let cluster = alloc(next, clusters, fat, count * ENTRY)?;
            assert_eq!(cluster, cluster_guess);
            for (child, node) in children {
                write_node(out, data_start, fat, next, clusters, child, node, cluster, &mut nested)?;
            }
            own.extend_from_slice(&nested);
            out[at(cluster)..at(cluster) + own.len()].copy_from_slice(&own);
            entries(parent, name, ATTR_DIRECTORY, cluster, 0);
        }
    }
    Ok(())
}

/// The next `bytes`' worth of clusters, contiguous and chained in `fat`: the first one.
fn alloc(next: &mut usize, clusters: usize, fat: &mut [u16], bytes: usize) -> Result<u16, String> {
    let count = bytes.div_ceil(CLUSTER).max(1);
    let first = *next;
    if first + count > clusters + 2 {
        return Err("the volume is full".into());
    }
    for (c, entry) in fat.iter_mut().enumerate().take(first + count).skip(first) {
        *entry = if c + 1 == first + count { 0xffff } else { (c + 1) as u16 };
    }
    *next += count;
    Ok(first as u16)
}

/// The 8.3 name for `name` if it is one already, upper case, or `None`.
fn short(name: &str) -> Option<[u8; 11]> {
    let (base, ext) = name.split_once('.').unwrap_or((name, ""));
    let valid = |s: &str, max: usize| s.len() <= max && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if base.is_empty() || !valid(base, 8) || !valid(ext, 3) {
        return None;
    }
    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Some(out)
}

fn lfn_count(name: &str) -> usize {
    if short(name).is_some() {
        0
    } else {
        name.encode_utf16().count().div_ceil(13)
    }
}

/// The checksum a long name's entries carry of their short name.
fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

/// `name`'s entries: long-name entries first, when it isn't 8.3, then its short entry.
fn entries(dir: &mut Vec<u8>, name: &str, attr: u8, cluster: u16, size: u32) {
    let short_name = short(name).unwrap_or_else(|| {
        // `BOOTRISCV64.EFI` → `BOOTRI~1EFI`: the first six usable characters, `~1`, and the extension's first three.
        let (base, ext) = name.rsplit_once('.').unwrap_or((name, ""));
        let clean = |s: &str, n: usize| -> Vec<u8> {
            s.bytes().filter(|b| b.is_ascii_alphanumeric()).map(|b| b.to_ascii_uppercase()).take(n).collect()
        };
        let mut out = [b' '; 11];
        let base = clean(base, 6);
        out[..base.len()].copy_from_slice(&base);
        out[base.len()..base.len() + 2].copy_from_slice(b"~1");
        let ext = clean(ext, 3);
        out[8..8 + ext.len()].copy_from_slice(&ext);
        out
    });
    if short(name).is_none() {
        let units: Vec<u16> = name.encode_utf16().collect();
        let count = units.len().div_ceil(13);
        let sum = checksum(&short_name);
        for seq in (1..=count).rev() {
            let mut e = [0u8; ENTRY];
            e[0] = seq as u8 | if seq == count { 0x40 } else { 0 };
            e[11] = ATTR_LFN;
            e[13] = sum;
            let chunk: Vec<u16> = (0..13)
                .map(|i| match (seq - 1) * 13 + i {
                    j if j < units.len() => units[j],
                    j if j == units.len() => 0,
                    _ => 0xffff,
                })
                .collect();
            for (i, u) in chunk.iter().enumerate() {
                let at = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30][i];
                e[at..at + 2].copy_from_slice(&u.to_le_bytes());
            }
            dir.extend_from_slice(&e);
        }
    }
    entry(dir, short_name, attr, cluster, size);
}

fn entry(dir: &mut Vec<u8>, name: [u8; 11], attr: u8, cluster: u16, size: u32) {
    let mut e = [0u8; ENTRY];
    e[..11].copy_from_slice(&name);
    e[11] = attr;
    e[16..18].copy_from_slice(&DATE.to_le_bytes());
    e[18..20].copy_from_slice(&DATE.to_le_bytes());
    e[24..26].copy_from_slice(&DATE.to_le_bytes());
    e[26..28].copy_from_slice(&cluster.to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    dir.extend_from_slice(&e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_83_or_get_a_long_name() {
        assert_eq!(short("BOOT.ELF"), Some(*b"BOOT    ELF"));
        assert_eq!(short("LANTERN"), Some(*b"LANTERN    "));
        assert_eq!(short("BOOTRISCV64.EFI"), None);
        assert_eq!(lfn_count("BOOTRISCV64.EFI"), 2);
        let mut dir = Vec::new();
        entries(&mut dir, "BOOTRISCV64.EFI", ATTR_ARCHIVE, 5, 10);
        assert_eq!(dir.len(), 3 * ENTRY);
        assert_eq!(dir[0], 0x42, "the last long entry first");
        assert_eq!(&dir[64..75], b"BOOTRI~1EFI");
        assert_eq!(dir[13], checksum(b"BOOTRI~1EFI"));
    }

    #[test]
    fn a_volume_fits_and_its_files_are_where_its_entries_say() {
        let mut v = Volume::default();
        v.add("EFI/BOOT/BOOTRISCV64.EFI", vec![0xaa; 5000]);
        v.add("LANTERN/BOOT.ELF", vec![0xbb; 3]);
        let mut out = vec![0u8; 65536 * SECTOR];
        v.write(&mut out, 2048).unwrap();
        assert_eq!(&out[54..62], b"FAT16   ");
        assert_eq!(&out[510..512], &[0x55, 0xaa]);
        // Find BOOT.ELF's bytes: the volume has exactly one run of three 0xbb.
        assert!(out.windows(4).any(|w| w == [0xbb, 0xbb, 0xbb, 0]));
        assert!(v.write(&mut vec![0u8; 1000 * SECTOR], 0).is_err(), "too small for FAT16");
    }
}
