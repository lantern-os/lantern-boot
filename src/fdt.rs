//! A small, hand-written flattened-device-tree (FDT / DTB) reader
//! ([RFC-0039](../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)).
//!
//! **Deliberately narrow, not a general-purpose FDT library**, the same discipline [`crate::elf`] follows
//! (RFC-0008/ADR-0012's TCB-impact reasoning). It reads a blob, walks its nodes in order, and answers what boot asks:
//! a node by path or phandle, a property's bytes, a `reg` entry at the parent's cell sizes, and the memory-reservation
//! block. What boot makes of that is [`crate::platform`]'s.
//!
//! **The tree is untrusted input** (`lantern-boot/THREAT_MODEL.md`): every offset is bounds-checked, nesting is limited to
//! [`MAX_DEPTH`], a cell count above 2 is refused, and anything malformed is an `Err`, never a permissive guess. Walking is
//! linear in the blob's size and allocates nothing.

// Not every binary uses every reader.
#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FdtError {
    TooShortForHeader,
    BadMagic,
    UnsupportedVersion(u32),
    StructBlockOutOfBounds,
    StringsBlockOutOfBounds,
    /// A token, name or property ran past the structure block, or an unknown token appeared.
    Truncated,
    /// Nodes nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// No `memory` node with a usable `reg`.
    NoMemoryNode,
    /// A `reg` too short for one entry at its parent's cell sizes, or a cell count this reader doesn't support.
    BadMemoryReg,
}

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

/// The device-tree specification's defaults when a node doesn't say.
const DEFAULT_ADDRESS_CELLS: u32 = 2;
const DEFAULT_SIZE_CELLS: u32 = 1;

/// The deepest nesting accepted. Real trees are 4 or 5 deep.
pub const MAX_DEPTH: usize = 16;

fn be32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes.get(off..off.checked_add(4)?).map(|b| u32::from_be_bytes(b.try_into().unwrap()))
}

fn be64(bytes: &[u8], off: usize) -> Option<u64> {
    bytes.get(off..off.checked_add(8)?).map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// The size the blob says it is, for mapping it before parsing.
///
/// # Safety
/// `dtb` must point to at least 8 readable bytes, and then to the whole blob.
pub unsafe fn total_size(dtb: *const u8) -> Result<usize, FdtError> {
    // SAFETY: the caller guarantees 8 readable bytes.
    let head = unsafe { core::slice::from_raw_parts(dtb, 8) };
    if be32(head, 0) != Some(FDT_MAGIC) {
        return Err(FdtError::BadMagic);
    }
    Ok(be32(head, 4).unwrap() as usize)
}

/// A checked device tree.
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    blob: &'a [u8],
    /// `[off_struct, struct_end)` of `blob`.
    off_struct: usize,
    struct_end: usize,
    strings: &'a [u8],
    off_rsvmap: usize,
}

/// One node, as the walk found it.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    fdt: Fdt<'a>,
    /// Offset of the first token after the node's name: its properties, then its children.
    body: usize,
    pub name: &'a [u8],
    /// 0 for the root.
    pub depth: usize,
    /// The parent's `#address-cells` and `#size-cells`, which this node's `reg` uses.
    pub parent_cells: (u32, u32),
    /// This node's own, which its children's `reg` use.
    pub cells: (u32, u32),
}

impl<'a> Fdt<'a> {
    /// Checks the header and block bounds.
    pub fn new(blob: &'a [u8]) -> Result<Self, FdtError> {
        if blob.len() < 40 {
            return Err(FdtError::TooShortForHeader);
        }
        if be32(blob, 0) != Some(FDT_MAGIC) {
            return Err(FdtError::BadMagic);
        }
        let version = be32(blob, 20).unwrap();
        // v16 introduced the current structure-block layout; QEMU, OpenSBI and U-Boot all produce v17.
        if version < 16 {
            return Err(FdtError::UnsupportedVersion(version));
        }
        let total = (be32(blob, 4).unwrap() as usize).min(blob.len());
        let blob = &blob[..total];
        let off_struct = be32(blob, 8).unwrap() as usize;
        let off_strings = be32(blob, 12).unwrap() as usize;
        let off_rsvmap = be32(blob, 16).unwrap() as usize;
        let size_strings = be32(blob, 32).unwrap() as usize;
        let size_struct = be32(blob, 36).unwrap() as usize;
        let struct_end = off_struct.checked_add(size_struct).ok_or(FdtError::StructBlockOutOfBounds)?;
        if struct_end > blob.len() || off_struct < 40 {
            return Err(FdtError::StructBlockOutOfBounds);
        }
        let strings_end = off_strings.checked_add(size_strings).ok_or(FdtError::StringsBlockOutOfBounds)?;
        if strings_end > blob.len() {
            return Err(FdtError::StringsBlockOutOfBounds);
        }
        if off_rsvmap > blob.len() {
            return Err(FdtError::StructBlockOutOfBounds);
        }
        let fdt = Self { blob, off_struct, struct_end, strings: &blob[off_strings..strings_end], off_rsvmap };
        // One full walk up front, so later walks can't meet a malformed tree half-way through what they report.
        fdt.walk(|_| false)?;
        Ok(fdt)
    }

    fn token(&self, off: usize) -> Result<u32, FdtError> {
        if off.checked_add(4).is_none_or(|end| end > self.struct_end) {
            return Err(FdtError::Truncated);
        }
        be32(self.blob, off).ok_or(FdtError::Truncated)
    }

    /// The name at `off`, and the offset after it.
    fn name_at(&self, off: usize) -> Result<(&'a [u8], usize), FdtError> {
        let rest = self.blob.get(off..self.struct_end).ok_or(FdtError::Truncated)?;
        let len = rest.iter().position(|&b| b == 0).ok_or(FdtError::Truncated)?;
        Ok((&rest[..len], align4(off + len + 1)))
    }

    /// The property at `off` (just after its token): its name, value, and the offset after it.
    fn prop_at(&self, off: usize) -> Result<(&'a [u8], &'a [u8], usize), FdtError> {
        let len = self.token(off)? as usize;
        let nameoff = self.token(off + 4)? as usize;
        let start = off + 8;
        let end = start.checked_add(len).ok_or(FdtError::Truncated)?;
        if end > self.struct_end {
            return Err(FdtError::Truncated);
        }
        let name = self
            .strings
            .get(nameoff..)
            .and_then(|s| s.iter().position(|&b| b == 0).map(|p| &s[..p]))
            .ok_or(FdtError::StringsBlockOutOfBounds)?;
        Ok((name, &self.blob[start..end], align4(end)))
    }

    /// Calls `f` with every node, parents before children, until it returns `true`; gives that node, if any.
    pub fn walk(&self, mut f: impl FnMut(&Node<'a>) -> bool) -> Result<Option<Node<'a>>, FdtError> {
        // Each open node's own cell sizes, which its children use.
        let mut cells = [(DEFAULT_ADDRESS_CELLS, DEFAULT_SIZE_CELLS); MAX_DEPTH + 1];
        let mut depth = 0usize;
        let mut off = self.off_struct;
        loop {
            let token = self.token(off)?;
            off += 4;
            match token {
                FDT_BEGIN_NODE => {
                    if depth > MAX_DEPTH {
                        return Err(FdtError::TooDeep);
                    }
                    let (name, body) = self.name_at(off)?;
                    let parent_cells =
                        if depth == 0 { (DEFAULT_ADDRESS_CELLS, DEFAULT_SIZE_CELLS) } else { cells[depth - 1] };
                    let mut node = Node { fdt: *self, body, name, depth, parent_cells, cells: (0, 0) };
                    node.cells = (
                        node.u32_prop(b"#address-cells")?.unwrap_or(DEFAULT_ADDRESS_CELLS),
                        node.u32_prop(b"#size-cells")?.unwrap_or(DEFAULT_SIZE_CELLS),
                    );
                    cells[depth] = node.cells;
                    if f(&node) {
                        return Ok(Some(node));
                    }
                    depth += 1;
                    off = body;
                }
                FDT_END_NODE => {
                    depth = depth.checked_sub(1).ok_or(FdtError::Truncated)?;
                }
                FDT_PROP => {
                    let (_, _, next) = self.prop_at(off)?;
                    off = next;
                }
                FDT_NOP => {}
                FDT_END => return if depth == 0 { Ok(None) } else { Err(FdtError::Truncated) },
                _ => return Err(FdtError::Truncated),
            }
        }
    }

    /// The node at `path`, such as `/soc/serial@d4017000`. A component without a unit address also matches a node
    /// with one (`/memory` finds `/memory@80000000`), as the specification allows when it's unambiguous.
    pub fn find(&self, path: &[u8]) -> Result<Option<Node<'a>>, FdtError> {
        if path.first() != Some(&b'/') {
            return Ok(None);
        }
        let mut parts: [&[u8]; MAX_DEPTH + 1] = [&[]; MAX_DEPTH + 1];
        let mut n = 0;
        for part in path[1..].split(|&b| b == b'/').filter(|p| !p.is_empty()) {
            if n == MAX_DEPTH {
                return Ok(None);
            }
            parts[n] = part;
            n += 1;
        }
        // The walk visits nodes in order; `matched` is how many leading components the open path matches.
        let mut matched = 0usize;
        self.walk(|node| {
            if node.depth == 0 {
                return n == 0;
            }
            if node.depth <= matched {
                matched = node.depth - 1;
            }
            if node.depth == matched + 1 && name_matches(node.name, parts[matched]) {
                matched = node.depth;
                return matched == n;
            }
            false
        })
    }

    /// The node whose `phandle` is `phandle`.
    pub fn by_phandle(&self, phandle: u32) -> Result<Option<Node<'a>>, FdtError> {
        let mut error = None;
        let found = self.walk(|node| match node.u32_prop(b"phandle") {
            Ok(p) => p == Some(phandle),
            Err(e) => {
                error = Some(e);
                true
            }
        })?;
        match error {
            Some(e) => Err(e),
            None => Ok(found),
        }
    }

    /// The memory-reservation block's entries, `(address, size)`, at most `out.len()`; how many.
    pub fn mem_reservations(&self, out: &mut [(u64, u64)]) -> Result<usize, FdtError> {
        let mut n = 0;
        let mut off = self.off_rsvmap;
        loop {
            let address = be64(self.blob, off).ok_or(FdtError::Truncated)?;
            let size = be64(self.blob, off + 8).ok_or(FdtError::Truncated)?;
            if address == 0 && size == 0 {
                return Ok(n);
            }
            if n == out.len() {
                return Ok(n);
            }
            out[n] = (address, size);
            n += 1;
            off += 16;
        }
    }
}

/// `name` is `want`, or `want` is `name` without its `@unit`.
fn name_matches(name: &[u8], want: &[u8]) -> bool {
    name == want || (!want.contains(&b'@') && name.split(|&b| b == b'@').next() == Some(want))
}

impl<'a> Node<'a> {
    /// The property `name`'s bytes, if the node has it.
    pub fn prop(&self, name: &[u8]) -> Result<Option<&'a [u8]>, FdtError> {
        let mut off = self.body;
        loop {
            match self.fdt.token(off)? {
                FDT_PROP => {
                    let (pname, value, next) = self.fdt.prop_at(off + 4)?;
                    if pname == name {
                        return Ok(Some(value));
                    }
                    off = next;
                }
                FDT_NOP => off += 4,
                // Properties come before children: the first child, or the node's end, ends them.
                _ => return Ok(None),
            }
        }
    }

    /// A one-cell property. A value of the wrong length is malformed.
    pub fn u32_prop(&self, name: &[u8]) -> Result<Option<u32>, FdtError> {
        match self.prop(name)? {
            None => Ok(None),
            Some(v) if v.len() == 4 => Ok(Some(u32::from_be_bytes(v.try_into().unwrap()))),
            Some(_) => Err(FdtError::Truncated),
        }
    }

    /// A one- or two-cell property, such as `timebase-frequency`.
    pub fn u64_prop(&self, name: &[u8]) -> Result<Option<u64>, FdtError> {
        match self.prop(name)? {
            None => Ok(None),
            Some(v) if v.len() == 4 || v.len() == 8 => Ok(Some(read_cells(v))),
            Some(_) => Err(FdtError::Truncated),
        }
    }

    /// The property's value up to its first NUL: the first of a string list.
    pub fn str_prop(&self, name: &[u8]) -> Result<Option<&'a [u8]>, FdtError> {
        Ok(self.prop(name)?.map(|v| v.split(|&b| b == 0).next().unwrap_or(&[])))
    }

    /// Whether `compatible` lists `want`.
    pub fn is_compatible(&self, want: &[u8]) -> Result<bool, FdtError> {
        Ok(self.prop(b"compatible")?.is_some_and(|v| v.split(|&b| b == 0).any(|c| c == want)))
    }

    /// Whether `status` is absent, `okay` or `ok`.
    pub fn is_enabled(&self) -> Result<bool, FdtError> {
        Ok(match self.str_prop(b"status")? {
            None => true,
            Some(s) => s == b"okay" || s == b"ok",
        })
    }

    /// Entry `index` of `reg`, at the parent's cell sizes.
    pub fn reg(&self, index: usize) -> Result<Option<(u64, u64)>, FdtError> {
        let Some(value) = self.prop(b"reg")? else { return Ok(None) };
        read_reg(value, self.parent_cells.0, self.parent_cells.1, index)
    }

    /// Calls `f` with each of this node's direct children.
    pub fn children(&self, mut f: impl FnMut(&Node<'a>)) -> Result<(), FdtError> {
        let mut started = false;
        let (my_depth, my_body) = (self.depth, self.body);
        let mut done = false;
        // Walk from the start, so children get correct cell sizes, and stop once past this node.
        self.fdt.walk(|node| {
            if done {
                return true;
            }
            if node.body == my_body {
                started = true;
                return false;
            }
            if started {
                if node.depth <= my_depth {
                    done = true;
                    return true;
                }
                if node.depth == my_depth + 1 {
                    f(node);
                }
            }
            false
        })?;
        Ok(())
    }
}

/// Entry `index` of a `reg` value at these cell sizes, if it has that many.
pub fn read_reg(value: &[u8], addr_cells: u32, size_cells: u32, index: usize) -> Result<Option<(u64, u64)>, FdtError> {
    if !(1..=2).contains(&addr_cells) || size_cells > 2 {
        return Err(FdtError::BadMemoryReg);
    }
    let a = addr_cells as usize * 4;
    let s = size_cells as usize * 4;
    let start = index * (a + s);
    let Some(entry) = value.get(start..start + a + s) else {
        return if index == 0 && !value.is_empty() { Err(FdtError::BadMemoryReg) } else { Ok(None) };
    };
    Ok(Some((read_cells(&entry[..a]), read_cells(&entry[a..]))))
}

fn read_cells(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// The first `memory` node's first `(base, size)`: what the demos ask for. The system image uses
/// [`crate::platform`], which reads every region.
///
/// # Safety
/// `dtb` must point to a readable blob of the size its header gives.
pub unsafe fn ram_region(dtb: *const u8) -> Option<(u64, u64)> {
    // SAFETY: forwarded to this function's contract.
    let size = unsafe { total_size(dtb) }.ok()?;
    // SAFETY: `size` is the blob's own declared length; the contract says the whole blob is readable.
    let bytes = unsafe { core::slice::from_raw_parts(dtb, size) };
    parse_ram_region(bytes).ok()
}

/// The pure, host-testable core of [`ram_region`].
pub fn parse_ram_region(blob: &[u8]) -> Result<(u64, u64), FdtError> {
    let fdt = Fdt::new(blob)?;
    let mut error = None;
    let node = fdt.walk(|node| {
        if node.depth != 1 || !name_matches(node.name, b"memory") {
            return false;
        }
        match node.reg(0) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                error = Some(e);
                true
            }
        }
    })?;
    if let Some(e) = error {
        return Err(e);
    }
    node.and_then(|n| n.reg(0).ok().flatten()).ok_or(FdtError::NoMemoryNode)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal v17 blob builder, for trees the fixtures don't cover.
    pub struct Builder {
        st: Vec<u8>,
        strings: Vec<u8>,
        rsv: Vec<(u64, u64)>,
    }

    impl Builder {
        pub fn new() -> Self {
            Self { st: Vec::new(), strings: Vec::new(), rsv: Vec::new() }
        }
        fn name_off(&mut self, name: &[u8]) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name);
            self.strings.push(0);
            off
        }
        fn pad(&mut self) {
            while self.st.len() % 4 != 0 {
                self.st.push(0);
            }
        }
        pub fn begin(&mut self, name: &[u8]) -> &mut Self {
            self.st.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
            self.st.extend_from_slice(name);
            self.st.push(0);
            self.pad();
            self
        }
        pub fn end(&mut self) -> &mut Self {
            self.st.extend_from_slice(&FDT_END_NODE.to_be_bytes());
            self
        }
        pub fn prop(&mut self, name: &[u8], value: &[u8]) -> &mut Self {
            let off = self.name_off(name);
            self.st.extend_from_slice(&FDT_PROP.to_be_bytes());
            self.st.extend_from_slice(&(value.len() as u32).to_be_bytes());
            self.st.extend_from_slice(&off.to_be_bytes());
            self.st.extend_from_slice(value);
            self.pad();
            self
        }
        pub fn u32(&mut self, name: &[u8], v: u32) -> &mut Self {
            self.prop(name, &v.to_be_bytes())
        }
        pub fn cells(&mut self, name: &[u8], vs: &[u32]) -> &mut Self {
            let bytes: Vec<u8> = vs.iter().flat_map(|v| v.to_be_bytes()).collect();
            self.prop(name, &bytes)
        }
        pub fn reserve(&mut self, address: u64, size: u64) -> &mut Self {
            self.rsv.push((address, size));
            self
        }
        pub fn build(&mut self) -> Vec<u8> {
            let mut st = self.st.clone();
            st.extend_from_slice(&FDT_END.to_be_bytes());
            let mut rsv = Vec::new();
            for &(a, s) in self.rsv.iter().chain([(0, 0)].iter()) {
                rsv.extend_from_slice(&a.to_be_bytes());
                rsv.extend_from_slice(&s.to_be_bytes());
            }
            let off_rsv = 40;
            let off_struct = off_rsv + rsv.len();
            let off_strings = off_struct + st.len();
            let total = off_strings + self.strings.len();
            let mut dtb = Vec::new();
            for v in [
                FDT_MAGIC,
                total as u32,
                off_struct as u32,
                off_strings as u32,
                off_rsv as u32,
                17,
                16,
                0,
                self.strings.len() as u32,
                st.len() as u32,
            ] {
                dtb.extend_from_slice(&v.to_be_bytes());
            }
            dtb.extend_from_slice(&rsv);
            dtb.extend_from_slice(&st);
            dtb.extend_from_slice(&self.strings);
            dtb
        }
    }

    fn memory_tree(addr_cells: u32, size_cells: u32, reg: &[u32]) -> Vec<u8> {
        let mut b = Builder::new();
        b.begin(b"").u32(b"#address-cells", addr_cells).u32(b"#size-cells", size_cells);
        b.begin(b"chosen").prop(b"bootargs", b"whatever\0").end();
        b.begin(b"memory@80000000").prop(b"device_type", b"memory\0").cells(b"reg", reg).end();
        b.end().build()
    }

    #[test]
    fn reads_qemu_virt_style_2_2_cells() {
        let dtb = memory_tree(2, 2, &[0, 0x8000_0000, 0, 0x0800_0000]);
        assert_eq!(parse_ram_region(&dtb), Ok((0x8000_0000, 0x0800_0000)));
    }

    #[test]
    fn reads_1_1_cells() {
        let dtb = memory_tree(1, 1, &[0x8000_0000, 0x0400_0000]);
        assert_eq!(parse_ram_region(&dtb), Ok((0x8000_0000, 0x0400_0000)));
    }

    #[test]
    fn full_64_bit_base_and_size() {
        let dtb = memory_tree(2, 2, &[1, 0, 2, 0]);
        assert_eq!(parse_ram_region(&dtb), Ok((0x1_0000_0000, 0x2_0000_0000)));
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        let mut dtb = memory_tree(2, 2, &[0, 0x8000_0000, 0, 0x0800_0000]);
        dtb[0] ^= 0xFF;
        assert_eq!(parse_ram_region(&dtb), Err(FdtError::BadMagic));
        let dtb = memory_tree(2, 2, &[0, 0x8000_0000, 0, 0x0800_0000]);
        assert_eq!(parse_ram_region(&dtb[..20]), Err(FdtError::TooShortForHeader));
        // Every truncation of the structure block is an error, never a guess, and never a panic.
        for cut in 40..dtb.len() {
            let mut short = dtb[..cut].to_vec();
            short[4..8].copy_from_slice(&(cut as u32).to_be_bytes());
            assert!(parse_ram_region(&short).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn no_memory_node_is_an_error_not_a_guess() {
        let mut b = Builder::new();
        b.begin(b"").u32(b"#address-cells", 2).u32(b"#size-cells", 2);
        b.begin(b"chosen").end();
        let dtb = b.end().build();
        assert_eq!(parse_ram_region(&dtb), Err(FdtError::NoMemoryNode));
    }

    #[test]
    fn total_size_matches_the_header() {
        let dtb = memory_tree(2, 2, &[0, 0x8000_0000, 0, 0x0800_0000]);
        // SAFETY: a live Vec, at least 8 bytes.
        assert_eq!(unsafe { total_size(dtb.as_ptr()) }, Ok(dtb.len()));
    }

    #[test]
    fn paths_phandles_children_and_reservations() {
        let mut b = Builder::new();
        b.begin(b"").u32(b"#address-cells", 2).u32(b"#size-cells", 2);
        b.begin(b"soc").u32(b"#address-cells", 1).u32(b"#size-cells", 1);
        b.begin(b"serial@1000").cells(b"reg", &[0x1000, 0x100]).u32(b"phandle", 7).end();
        b.begin(b"serial@2000").cells(b"reg", &[0x2000, 0x100]).prop(b"status", b"disabled\0").end();
        b.end();
        b.begin(b"serial@3000").cells(b"reg", &[0, 0x3000, 0, 0x100]).end();
        b.end();
        b.reserve(0x8000_0000, 0x20_0000);
        let dtb = b.build();
        let fdt = Fdt::new(&dtb).unwrap();
        let node = fdt.find(b"/soc/serial@2000").unwrap().unwrap();
        assert_eq!(node.reg(0), Ok(Some((0x2000, 0x100))), "the parent's 1-cell sizes");
        assert!(!node.is_enabled().unwrap());
        let top = fdt.find(b"/serial@3000").unwrap().unwrap();
        assert_eq!(top.reg(0), Ok(Some((0x3000, 0x100))), "the root's 2-cell sizes, not the sibling's");
        assert!(fdt.find(b"/soc/serial@3000").unwrap().is_none());
        assert_eq!(fdt.by_phandle(7).unwrap().unwrap().name, b"serial@1000");
        let mut names = Vec::new();
        fdt.find(b"/soc").unwrap().unwrap().children(|c| names.push(c.name.to_vec())).unwrap();
        assert_eq!(names, vec![b"serial@1000".to_vec(), b"serial@2000".to_vec()]);
        let mut rsv = [(0, 0); 4];
        assert_eq!(fdt.mem_reservations(&mut rsv), Ok(1));
        assert_eq!(rsv[0], (0x8000_0000, 0x20_0000));
    }

    #[test]
    fn too_deep_is_refused() {
        let mut b = Builder::new();
        for _ in 0..=MAX_DEPTH + 1 {
            b.begin(b"n");
        }
        for _ in 0..=MAX_DEPTH + 1 {
            b.end();
        }
        assert_eq!(Fdt::new(&b.build()).err(), Some(FdtError::TooDeep));
    }

    /// The fixtures: QEMU 10.2's `virt` trees (PLIC, and AIA) and the K3 Pico-ITX's, from SpacemiT's Linux tree
    /// (`testdata/README.md`).
    pub fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn every_fixture_parses_and_no_corruption_panics() {
        for name in ["qemu-virt.dtb", "qemu-virt-aia.dtb", "k3-pico-itx.dtb"] {
            let dtb = fixture(name);
            let fdt = Fdt::new(&dtb).unwrap();
            assert!(fdt.find(b"/cpus").unwrap().is_some(), "{name}");
            // A changed byte anywhere is either still a tree or an error: never a panic or a hang.
            for at in (0..dtb.len()).step_by(dtb.len() / 997 + 1) {
                let mut bad = dtb.clone();
                bad[at] ^= 0xa5;
                if let Ok(fdt) = Fdt::new(&bad) {
                    let _ = fdt.find(b"/soc/serial@d4017000");
                    let _ = fdt.by_phandle(3);
                }
            }
        }
    }
}
