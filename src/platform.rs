//! The machine LanternOS booted on, read from its device tree
//! ([RFC-0039](../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md) §1).
//!
//! Everything boot used to take from QEMU `virt`'s fixed layout comes from here instead: RAM and what's reserved inside
//! it, the timer's frequency, the console UART, the interrupt controller (a PLIC, or AIA's APLIC and IMSIC) and the boot
//! hart's place in it, and the virtio-mmio devices. QEMU is no special case: its values are read from its tree as the
//! K3's are.
//!
//! A tree this can't use is an [`PlatformError`], which boot prints and stops on. Nothing is guessed.

#![allow(dead_code)]

use crate::fdt::{Fdt, FdtError, Node};

/// The most RAM regions, reserved regions and virtio-mmio devices recorded. More is an error, never a silent truncation.
pub const MAX_RAM: usize = 8;
pub const MAX_RESERVED: usize = 128;
pub const MAX_VIRTIO: usize = 8;

/// A physical range, `[base, base + size)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Region {
    pub base: u64,
    pub size: u64,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
}

/// A 16550-compatible UART, as the firmware left it: set up, at its baud rate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Uart {
    pub base: u64,
    pub size: u64,
    /// Registers are `1 << reg_shift` bytes apart.
    pub reg_shift: u32,
    /// Each register is accessed this many bytes wide: 1 or 4.
    pub io_width: u32,
    /// Its interrupt line on [`Platform::intc`].
    pub irq: u32,
    /// An XScale-style UART (the K3's), whose interrupt-enable register also has a unit-enable bit and a receive
    /// time-out interrupt that a driver must keep set.
    pub xscale: bool,
}

/// The supervisor-level interrupt controller, and the boot hart's place in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Intc {
    /// A PLIC: its registers, the boot hart's S-mode context, and how many lines (line 0 means "none").
    Plic { base: u64, size: u64, context: u32, lines: u32 },
    /// AIA: the supervisor-level APLIC in MSI mode, delivering to the boot hart's supervisor IMSIC interrupt file.
    Aia {
        aplic_base: u64,
        aplic_size: u64,
        /// Sources 1 to `sources`.
        sources: u32,
        /// The boot hart's index in the APLIC's MSI target encoding.
        hart_index: u32,
        /// The boot hart's supervisor interrupt file, which MSIs are written to.
        imsic_file: u64,
        /// Interrupt identities 1 to `ids`.
        ids: u32,
    },
}

/// A device and its interrupt line on [`Platform::intc`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Device {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
}

/// A memory window of a PCIe host: CPU addresses `[cpu, cpu + size)` reach bus addresses `[pci, pci + size)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Window {
    pub cpu: u64,
    pub pci: u64,
    pub size: u64,
}

/// The most INTx routes recorded: QEMU's map has 4 devices by 4 pins.
pub const MAX_INTX: usize = 32;

/// A PCIe host with an ECAM configuration space (`pci-host-ecam-generic`, QEMU `virt`'s) (RFC-0039 §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PciHost {
    /// Configuration space: bus `b`, device `d`, function `f` at `ecam.base + (b << 20 | d << 15 | f << 12)`.
    pub ecam: Region,
    pub bus_first: u32,
    pub bus_last: u32,
    /// Its 32-bit non-prefetchable memory window, for BARs the firmware didn't assign.
    pub mem32: Option<Window>,
    /// Its 64-bit non-prefetchable memory window, where firmware (EDK2) may have put a 64-bit BAR.
    pub mem64: Option<Window>,
    /// `interrupt-map-mask`'s first cell, over a function's `bus << 16 | device << 11 | function << 8`.
    intx_mask: u32,
    /// `(masked address, pin, line)`: INTx routes to [`Platform::intc`].
    intx: [(u32, u32, u32); MAX_INTX],
    intx_n: usize,
}

impl PciHost {
    /// The line on [`Platform::intc`] that `device`'s INTx `pin` (1 to 4) reaches, on the host's root bus.
    pub fn intx_line(&self, bus: u32, device: u32, function: u32, pin: u32) -> Option<u32> {
        let address = (bus << 16 | device << 11 | function << 8) & self.intx_mask;
        self.intx[..self.intx_n].iter().find(|&&(a, p, _)| a == address && p == pin).map(|&(_, _, line)| line)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlatformError {
    Fdt(FdtError),
    /// No `/cpus` node with a `cpu` whose `reg` is the boot hart.
    BootHartNotFound,
    /// No `timebase-frequency`, or zero.
    NoTimebase,
    /// No `/chosen/stdout-path`, or it names nothing.
    NoConsole,
    /// The console isn't a 16550-compatible UART, or its `reg-shift`/`reg-io-width` aren't supported.
    ConsoleUnsupported,
    /// Neither a PLIC with an S-mode context for the boot hart, nor an MSI-mode APLIC with a supervisor IMSIC for it.
    NoInterruptController,
    /// No usable RAM.
    NoMemory,
    /// DMA isn't cache-coherent, and the boot hart lacks `Svpbmt` or `Zicbom`, so DMA buffers can't be kept coherent.
    DmaCantBeCoherent,
    /// More RAM, reserved or virtio regions than recorded.
    TooMany,
    /// The EFI loader's hand-off of reserved memory is malformed: not a page inside RAM, or longer than one.
    BadHandoff,
}

impl From<FdtError> for PlatformError {
    fn from(e: FdtError) -> Self {
        Self::Fdt(e)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Platform {
    pub boot_hart: u64,
    pub timebase_hz: u64,
    /// The boot hart has `Svpbmt` (page-based memory types) and `Zicbom` (cache-block management), with this block size.
    pub svpbmt: bool,
    pub zicbom: bool,
    pub cbom_block: u64,
    /// Some bus in the tree says its devices' DMA doesn't snoop the caches (`dma-noncoherent`): the K3's does.
    pub dma_noncoherent: bool,
    pub uart: Uart,
    pub intc: Intc,
    ram: [Region; MAX_RAM],
    ram_n: usize,
    reserved: [Region; MAX_RESERVED],
    reserved_n: usize,
    virtio: [Device; MAX_VIRTIO],
    virtio_n: usize,
    pub pci: Option<PciHost>,
}

/// The compatible strings of UARTs this console drives: all 16550 register layouts.
const UARTS: [&[u8]; 5] = [b"ns16550a", b"ns16550", b"snps,dw-apb-uart", b"intel,xscale-uart", b"spacemit,k1-uart"];

/// `interrupts-extended` cause numbers: supervisor and machine external interrupts.
const S_EXTERNAL: u32 = 9;

fn push<const N: usize, T: Copy>(arr: &mut [T; N], n: &mut usize, v: T) -> Result<(), PlatformError> {
    if *n == N {
        return Err(PlatformError::TooMany);
    }
    arr[*n] = v;
    *n += 1;
    Ok(())
}

/// The `(phandle, cause)` pairs of a node's `interrupts-extended`, for controllers with one-cell specifiers (every hart's
/// `riscv,cpu-intc`), calling `f(index, phandle, cause)`.
fn each_extended(node: &Node, mut f: impl FnMut(usize, u32, u32)) -> Result<(), PlatformError> {
    let Some(v) = node.prop(b"interrupts-extended")? else { return Ok(()) };
    if v.len() % 8 != 0 {
        return Err(FdtError::Truncated.into());
    }
    for (i, pair) in v.chunks_exact(8).enumerate() {
        f(i, u32::from_be_bytes(pair[..4].try_into().unwrap()), u32::from_be_bytes(pair[4..].try_into().unwrap()));
    }
    Ok(())
}

impl Platform {
    /// Reads the machine from `blob`, for the hart boot is running on.
    pub fn parse(blob: &[u8], boot_hart: u64) -> Result<Self, PlatformError> {
        let fdt = Fdt::new(blob)?;
        let cpus = fdt.find(b"/cpus")?.ok_or(PlatformError::BootHartNotFound)?;

        // The boot hart's `cpu` node, its own `riscv,cpu-intc`'s phandle, and the timer's frequency.
        let mut cpu = None;
        let mut err = None;
        cpus.children(|c| {
            if cpu.is_some() || err.is_some() {
                return;
            }
            match (c.str_prop(b"device_type"), c.reg(0)) {
                (Ok(Some(b"cpu")), Ok(Some((hart, _)))) if hart == boot_hart => cpu = Some(*c),
                (Err(e), _) | (_, Err(e)) => err = Some(e),
                _ => {}
            }
        })?;
        if let Some(e) = err {
            return Err(e.into());
        }
        let cpu = cpu.ok_or(PlatformError::BootHartNotFound)?;
        let mut hart_intc = None;
        cpu.children(|c| {
            if c.is_compatible(b"riscv,cpu-intc").unwrap_or(false) {
                hart_intc = c.u32_prop(b"phandle").ok().flatten();
            }
        })?;
        let hart_intc = hart_intc.ok_or(PlatformError::NoInterruptController)?;
        let timebase_hz = match cpus.u64_prop(b"timebase-frequency")? {
            Some(hz) => hz,
            None => cpu.u64_prop(b"timebase-frequency")?.unwrap_or(0),
        };
        if timebase_hz == 0 {
            return Err(PlatformError::NoTimebase);
        }

        // `riscv,isa-extensions` (a string list) or, in older trees, the `riscv,isa` string's `_`-separated names.
        let has = |name: &[u8]| -> Result<bool, PlatformError> {
            if let Some(list) = cpu.prop(b"riscv,isa-extensions")? {
                return Ok(list.split(|&b| b == 0).any(|e| e == name));
            }
            Ok(cpu.str_prop(b"riscv,isa")?.is_some_and(|isa| isa.split(|&b| b == b'_').skip(1).any(|e| e == name)))
        };
        let (svpbmt, zicbom) = (has(b"svpbmt")?, has(b"zicbom")?);
        let cbom_block = if zicbom { cpu.u32_prop(b"riscv,cbom-block-size")?.unwrap_or(0) as u64 } else { 0 };
        let mut dma_noncoherent = false;
        fdt.walk(|node| {
            dma_noncoherent |= node.prop(b"dma-noncoherent").ok().flatten().is_some() && node.is_enabled().unwrap_or(false);
            false
        })?;
        if dma_noncoherent && !(svpbmt && zicbom && cbom_block.is_power_of_two()) {
            return Err(PlatformError::DmaCantBeCoherent);
        }
        let (mut uart, uart_node) = Self::console(&fdt)?;
        let (intc, intc_phandle) = Self::interrupt_controller(&fdt, hart_intc)?;
        uart.irq = Self::interrupt_of(&fdt, &uart_node, intc_phandle)?.ok_or(PlatformError::ConsoleUnsupported)?;

        let mut platform = Self {
            boot_hart,
            timebase_hz,
            svpbmt,
            zicbom,
            cbom_block,
            dma_noncoherent,
            uart,
            intc,
            ram: [Region::default(); MAX_RAM],
            ram_n: 0,
            reserved: [Region::default(); MAX_RESERVED],
            reserved_n: 0,
            virtio: [Device::default(); MAX_VIRTIO],
            virtio_n: 0,
            pci: None,
        };
        platform.memory(&fdt)?;
        platform.devices(&fdt, intc_phandle)?;
        platform.pci = Self::pci_host(&fdt, intc_phandle)?;
        Ok(platform)
    }

    /// `/chosen/stdout-path`, through `/aliases` if it isn't a path, without its `:options`.
    fn console<'a>(fdt: &Fdt<'a>) -> Result<(Uart, Node<'a>), PlatformError> {
        let chosen = fdt.find(b"/chosen")?.ok_or(PlatformError::NoConsole)?;
        let path = chosen.str_prop(b"stdout-path")?.ok_or(PlatformError::NoConsole)?;
        let path = path.split(|&b| b == b':').next().unwrap_or(&[]);
        let node = if path.first() == Some(&b'/') {
            fdt.find(path)?
        } else {
            let aliases = fdt.find(b"/aliases")?.ok_or(PlatformError::NoConsole)?;
            match aliases.str_prop(path)? {
                Some(target) => fdt.find(target)?,
                None => None,
            }
        };
        let node = node.ok_or(PlatformError::NoConsole)?;
        let mut supported = false;
        for c in UARTS {
            supported |= node.is_compatible(c)?;
        }
        if !supported {
            return Err(PlatformError::ConsoleUnsupported);
        }
        let (base, size) = node.reg(0)?.ok_or(PlatformError::NoConsole)?;
        let reg_shift = node.u32_prop(b"reg-shift")?.unwrap_or(0);
        let io_width = node.u32_prop(b"reg-io-width")?.unwrap_or(1);
        if reg_shift > 2 || !(io_width == 1 || io_width == 4) {
            return Err(PlatformError::ConsoleUnsupported);
        }
        let xscale = node.is_compatible(b"intel,xscale-uart")? || node.is_compatible(b"spacemit,k1-uart")?;
        Ok((Uart { base, size, reg_shift, io_width, irq: 0, xscale }, node))
    }

    /// The supervisor-level controller for `hart_intc`, and its phandle, which devices' `interrupt-parent` names.
    /// AIA is preferred when a tree has both.
    fn interrupt_controller(fdt: &Fdt, hart_intc: u32) -> Result<(Intc, u32), PlatformError> {
        // A supervisor IMSIC with a file for this hart: its phandle, the file's address, its identity count.
        let mut imsic: Option<(u32, u64, u32, u32)> = None;
        let mut plic: Option<(Intc, u32)> = None;
        let mut err: Option<PlatformError> = None;
        fdt.walk(|node| {
            let r: Result<(), PlatformError> = (|| {
                if !node.is_enabled()? {
                    return Ok(());
                }
                if node.is_compatible(b"riscv,imsics")? {
                    let mut index = None;
                    each_extended(node, |i, ph, cause| {
                        if ph == hart_intc && cause == S_EXTERNAL {
                            index = Some(i);
                        }
                    })?;
                    if let (Some(i), Some(ph)) = (index, node.u32_prop(b"phandle")?) {
                        let guest_bits = node.u32_prop(b"riscv,guest-index-bits")?.unwrap_or(0);
                        if guest_bits > 6 {
                            return Err(PlatformError::NoInterruptController);
                        }
                        let (base, size) = node.reg(0)?.ok_or(PlatformError::NoInterruptController)?;
                        let file = base + ((i as u64) << (12 + guest_bits));
                        if file + 0x1000 > base + size {
                            return Err(PlatformError::NoInterruptController);
                        }
                        let ids = node.u32_prop(b"riscv,num-ids")?.unwrap_or(0);
                        imsic = Some((ph, file, ids, i as u32));
                    }
                } else if node.is_compatible(b"riscv,plic0")? || node.is_compatible(b"sifive,plic-1.0.0")? {
                    let mut context = None;
                    each_extended(node, |i, ph, cause| {
                        if ph == hart_intc && cause == S_EXTERNAL && context.is_none() {
                            context = Some(i as u32);
                        }
                    })?;
                    if let (Some(context), Some(ph)) = (context, node.u32_prop(b"phandle")?) {
                        let (base, size) = node.reg(0)?.ok_or(PlatformError::NoInterruptController)?;
                        let lines = node.u32_prop(b"riscv,ndev")?.unwrap_or(0) + 1;
                        plic = Some((Intc::Plic { base, size, context, lines }, ph));
                    }
                }
                Ok(())
            })();
            if let Err(e) = r {
                err = Some(e);
                return true;
            }
            false
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        if let Some((imsic_ph, imsic_file, ids, hart_index)) = imsic {
            // The supervisor APLIC: the one delivering, as MSIs, to that IMSIC.
            let mut aplic = None;
            fdt.walk(|node| {
                if node.is_compatible(b"riscv,aplic").unwrap_or(false)
                    && node.is_enabled().unwrap_or(false)
                    && node.u32_prop(b"msi-parent").ok().flatten() == Some(imsic_ph)
                {
                    aplic = Some(*node);
                    return true;
                }
                false
            })?;
            if let Some(node) = aplic {
                let (aplic_base, aplic_size) = node.reg(0)?.ok_or(PlatformError::NoInterruptController)?;
                let sources = node.u32_prop(b"riscv,num-sources")?.unwrap_or(0);
                let ph = node.u32_prop(b"phandle")?.ok_or(PlatformError::NoInterruptController)?;
                if sources == 0 || ids == 0 {
                    return Err(PlatformError::NoInterruptController);
                }
                return Ok((Intc::Aia { aplic_base, aplic_size, sources, hart_index, imsic_file, ids }, ph));
            }
        }
        plic.ok_or(PlatformError::NoInterruptController)
    }

    /// Every `memory` node's `reg` entries, and every reservation: `/reserved-memory`'s enabled children and the
    /// memory-reservation block.
    fn memory(&mut self, fdt: &Fdt) -> Result<(), PlatformError> {
        let mut err = None;
        let (mut ram, mut ram_n) = (self.ram, 0);
        fdt.walk(|node| {
            let is_memory = node.depth == 1
                && (node.str_prop(b"device_type").ok().flatten() == Some(b"memory")
                    || node.name == b"memory"
                    || node.name.starts_with(b"memory@"));
            if is_memory && node.is_enabled().unwrap_or(false) {
                for i in 0.. {
                    match node.reg(i) {
                        Ok(Some((base, size))) if size > 0 => {
                            if let Err(e) = push(&mut ram, &mut ram_n, Region { base, size }) {
                                err = Some(e);
                                return true;
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(e) => {
                            err = Some(e.into());
                            return true;
                        }
                    }
                }
            }
            false
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        if ram_n == 0 {
            return Err(PlatformError::NoMemory);
        }
        (self.ram, self.ram_n) = (ram, ram_n);

        let mut block = [(0u64, 0u64); MAX_RESERVED];
        let n = fdt.mem_reservations(&mut block)?;
        for &(base, size) in &block[..n] {
            self.reserve(Region { base, size })?;
        }
        if let Some(resmem) = fdt.find(b"/reserved-memory")? {
            let mut regions = [Region::default(); MAX_RESERVED];
            let mut count = 0;
            let mut err = None;
            resmem.children(|c| {
                if err.is_some() || !c.is_enabled().unwrap_or(true) {
                    return;
                }
                for i in 0.. {
                    match c.reg(i) {
                        Ok(Some((base, size))) => {
                            if let Err(e) = push(&mut regions, &mut count, Region { base, size }) {
                                err = Some(e);
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            err = Some(e.into());
                            return;
                        }
                    }
                }
            })?;
            if let Some(e) = err {
                return Err(e);
            }
            for &r in &regions[..count] {
                self.reserve(r)?;
            }
        }
        Ok(())
    }

    /// Adds `r` to what's reserved: the device tree itself, say, or the kernel image.
    pub fn reserve(&mut self, r: Region) -> Result<(), PlatformError> {
        if r.size == 0 {
            return Ok(());
        }
        push(&mut self.reserved, &mut self.reserved_n, r)
    }

    /// The first enabled `pci-host-ecam-generic` node, if any.
    fn pci_host(fdt: &Fdt, intc: u32) -> Result<Option<PciHost>, PlatformError> {
        let mut found = None;
        fdt.walk(|node| {
            if node.is_compatible(b"pci-host-ecam-generic").unwrap_or(false) && node.is_enabled().unwrap_or(false) {
                found = Some(*node);
                return true;
            }
            false
        })?;
        let Some(node) = found else { return Ok(None) };
        let (base, size) = node.reg(0)?.ok_or(FdtError::Truncated)?;
        let (bus_first, bus_last) = match node.prop(b"bus-range")? {
            Some(v) if v.len() == 8 => {
                (u32::from_be_bytes(v[..4].try_into().unwrap()), u32::from_be_bytes(v[4..].try_into().unwrap()))
            }
            Some(_) => return Err(FdtError::Truncated.into()),
            None => (0, 255),
        };
        let cell = |v: &[u8], i: usize| -> Result<u32, PlatformError> {
            v.get(i * 4..i * 4 + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap())).ok_or(FdtError::Truncated.into())
        };
        let cells64 = |v: &[u8], i: usize, n: u32| -> Result<u64, PlatformError> {
            Ok(if n == 2 { (cell(v, i)? as u64) << 32 | cell(v, i + 1)? as u64 } else { cell(v, i)? as u64 })
        };
        // `ranges`: a 3-cell bus address, the parent's address, the host's size cells.
        let (parent_addr, size_cells) = (node.parent_cells.0, node.cells.1);
        if node.cells.0 != 3 || !(1..=2).contains(&parent_addr) || !(1..=2).contains(&size_cells) {
            return Err(FdtError::BadMemoryReg.into());
        }
        let (mut mem32, mut mem64) = (None, None);
        if let Some(v) = node.prop(b"ranges")? {
            let entry = 3 + parent_addr as usize + size_cells as usize;
            if v.len() % (entry * 4) != 0 {
                return Err(FdtError::Truncated.into());
            }
            for e in 0..v.len() / (entry * 4) {
                let at = e * entry;
                let hi = cell(v, at)?;
                let pci = (cell(v, at + 1)? as u64) << 32 | cell(v, at + 2)? as u64;
                let cpu = cells64(v, at + 3, parent_addr)?;
                let size = cells64(v, at + 3 + parent_addr as usize, size_cells)?;
                // Space code 2: 32-bit memory, 3: 64-bit; bit 30: prefetchable.
                let window = Some(Window { cpu, pci, size });
                match ((hi >> 24) & 3, hi & (1 << 30) != 0) {
                    (2, false) if mem32.is_none() => mem32 = window,
                    (3, false) if mem64.is_none() => mem64 = window,
                    _ => {}
                }
            }
        }
        // `interrupt-map`: a 3-cell address and a pin, the parent's phandle, its address cells and its interrupt cells.
        let mut host = PciHost {
            ecam: Region { base, size },
            bus_first,
            bus_last,
            mem32,
            mem64,
            intx_mask: 0,
            intx: [(0, 0, 0); MAX_INTX],
            intx_n: 0,
        };
        if let (Some(mask), Some(map)) = (node.prop(b"interrupt-map-mask")?, node.prop(b"interrupt-map")?) {
            host.intx_mask = cell(mask, 0)?;
            let mut i = 0;
            while i * 4 < map.len() {
                let (address, pin, phandle) = (cell(map, i)?, cell(map, i + 3)?, cell(map, i + 4)?);
                let parent = fdt.by_phandle(phandle)?.ok_or(PlatformError::NoInterruptController)?;
                let parent_address = parent.u32_prop(b"#address-cells")?.unwrap_or(0) as usize;
                let parent_interrupt = parent.u32_prop(b"#interrupt-cells")?.unwrap_or(1) as usize;
                if parent_interrupt == 0 {
                    return Err(FdtError::Truncated.into());
                }
                let line = cell(map, i + 5 + parent_address)?;
                if phandle == intc {
                    push(&mut host.intx, &mut host.intx_n, (address & host.intx_mask, pin, line))?;
                }
                i += 5 + parent_address + parent_interrupt;
            }
        }
        Ok(Some(host))
    }

    /// `target`'s first interrupt, if its `interrupt-parent` (its own, or inherited) is `intc`.
    fn interrupt_of(fdt: &Fdt, target: &Node, intc: u32) -> Result<Option<u32>, PlatformError> {
        let mut parents = [0u32; crate::fdt::MAX_DEPTH + 1];
        let mut parent = None;
        fdt.walk(|node| {
            let inherited = if node.depth == 0 { 0 } else { parents[node.depth - 1] };
            parents[node.depth] = node.u32_prop(b"interrupt-parent").ok().flatten().unwrap_or(inherited);
            if node.name == target.name && node.depth == target.depth && node.reg(0).ok() == target.reg(0).ok() {
                parent = Some(parents[node.depth]);
                return true;
            }
            false
        })?;
        if parent != Some(intc) {
            return Ok(None);
        }
        let Some(irqs) = target.prop(b"interrupts")? else { return Ok(None) };
        Ok(Some(irqs.get(..4).map(|b| u32::from_be_bytes(b.try_into().unwrap())).ok_or(FdtError::Truncated)?))
    }

    /// Enabled `virtio,mmio` nodes whose interrupts go to `intc`, lowest address first.
    fn devices(&mut self, fdt: &Fdt, intc: u32) -> Result<(), PlatformError> {
        // `interrupt-parent` is inherited: each open depth's effective parent.
        let mut parents = [0u32; crate::fdt::MAX_DEPTH + 1];
        let mut err = None;
        let (mut found, mut n) = (self.virtio, 0);
        fdt.walk(|node| {
            let inherited = if node.depth == 0 { 0 } else { parents[node.depth - 1] };
            let parent = node.u32_prop(b"interrupt-parent").ok().flatten().unwrap_or(inherited);
            parents[node.depth] = parent;
            let r: Result<(), PlatformError> = (|| {
                if !node.is_compatible(b"virtio,mmio")? || !node.is_enabled()? || parent != intc {
                    return Ok(());
                }
                let Some((base, size)) = node.reg(0)? else { return Ok(()) };
                let Some(irqs) = node.prop(b"interrupts")? else { return Ok(()) };
                let irq = irqs.get(..4).map(|b| u32::from_be_bytes(b.try_into().unwrap())).ok_or(FdtError::Truncated)?;
                push(&mut found, &mut n, Device { base, size, irq })
            })();
            if let Err(e) = r {
                err = Some(e);
                return true;
            }
            false
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        found[..n].sort_unstable_by_key(|d| d.base);
        (self.virtio, self.virtio_n) = (found, n);
        Ok(())
    }

    pub fn ram(&self) -> &[Region] {
        &self.ram[..self.ram_n]
    }

    pub fn reserved(&self) -> &[Region] {
        &self.reserved[..self.reserved_n]
    }

    pub fn virtio(&self) -> &[Device] {
        &self.virtio[..self.virtio_n]
    }

    /// The largest run of RAM nothing reserves, trimmed inward to `align` (a power of two): what boot gives the kernel
    /// as untyped memory.
    pub fn largest_free(&self, align: u64) -> Option<Region> {
        let mut best: Option<Region> = None;
        for ram in self.ram() {
            // Walk the region, stepping past each reservation that overlaps what's left of it.
            let mut start = ram.base;
            loop {
                // The first reservation overlapping [start, ram.end()).
                let next = self
                    .reserved()
                    .iter()
                    .filter(|r| r.base < ram.end() && r.end() > start)
                    .min_by_key(|r| r.base.max(start));
                let gap_end = next.map_or(ram.end(), |r| r.base.max(start));
                let lo = start.checked_add(align - 1).map(|v| v & !(align - 1));
                let hi = gap_end & !(align - 1);
                if let Some(lo) = lo {
                    if hi > lo && best.is_none_or(|b| hi - lo > b.size) {
                        best = Some(Region { base: lo, size: hi - lo });
                    }
                }
                match next {
                    Some(r) if r.end() < ram.end() => start = r.end(),
                    _ => break,
                }
            }
        }
        best
    }
}

/// The machine boot runs on, once [`discover`] has read it.
#[cfg(target_arch = "riscv64")]
struct PlatformCell(core::cell::UnsafeCell<Option<Platform>>);
// SAFETY: written once, by `discover`, before anything reads it; boot is single-hart (ADR-0010).
#[cfg(target_arch = "riscv64")]
unsafe impl Sync for PlatformCell {}
#[cfg(target_arch = "riscv64")]
static PLATFORM: PlatformCell = PlatformCell(core::cell::UnsafeCell::new(None));

/// The machine, as [`discover`] read it.
#[cfg(target_arch = "riscv64")]
pub fn get() -> &'static Platform {
    // SAFETY: only written by `discover`, before any caller of this can run.
    unsafe { (*PLATFORM.0.get()).as_ref() }.expect("platform::discover must run first")
}

/// Stops boot, saying why: a machine boot can't describe isn't one it guesses about.
#[cfg(target_arch = "riscv64")]
fn refuse(why: &dyn core::fmt::Debug) -> ! {
    crate::println!("boot: this machine can't be used: {why:?}");
    loop {
        core::hint::spin_loop();
    }
}

/// Reads the machine from the device tree the firmware passed, and sets boot up for it: the console moves to the tree's
/// UART, the HAL learns the interrupt controller and timer rate, and [`crate::pmm`] gets the largest run of free RAM.
/// Stops, with the reason on the SBI console, if the tree can't be used.
///
/// # Safety
/// Once, first thing in `boot_main`, with the `a0`/`a1` the firmware passed: `dtb` a readable device tree, and the MMU
/// off.
#[cfg(target_arch = "riscv64")]
pub unsafe fn discover(hartid: usize, dtb: usize) -> &'static Platform {
    let mega = lantern_hal::RISCV64_MEGAPAGE_SIZE as u64;
    // SAFETY: the contract: `dtb` is the firmware's device tree.
    let size = match unsafe { crate::fdt::total_size(dtb as *const u8) } {
        Ok(size) => size,
        Err(e) => refuse(&e),
    };
    // SAFETY: as above; `size` is the blob's own length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, size) };
    let mut p = match Platform::parse(blob, hartid as u64) {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    // SAFETY: the tree's console, identity-reachable with the MMU off, set up by the firmware.
    unsafe { crate::uart::use_uart(p.uart.base as usize, p.uart.reg_shift, p.uart.io_width) };
    let intc = match p.intc {
        Intc::Plic { base, context, lines, .. } => {
            lantern_hal::Riscv64Intc::Plic { base: base as usize, context: context as usize, lines }
        }
        Intc::Aia { aplic_base, sources, hart_index, ids, .. } => {
            lantern_hal::Riscv64Intc::Aia { aplic_base: aplic_base as usize, sources, hart_index, ids }
        }
    };
    // RFC-0039 §5: DMA frames uncached wherever the CPU can, cleaned after zeroing where it can do that too.
    let dma_uncached = p.svpbmt;
    let cbom_block = if dma_uncached && p.zicbom { p.cbom_block as usize } else { 0 };
    // SAFETY: once, before interrupts are set up or any thread runs.
    unsafe {
        lantern_hal::riscv64_configure(lantern_hal::Riscv64Platform {
            intc,
            timebase_hz: p.timebase_hz,
            dma_uncached,
            cbom_block,
        })
    };

    // Not free: what the EFI loader says the firmware keeps (RFC-0039), when it started this image.
    if let Err(e) = reserve_firmware_memory(&mut p) {
        refuse(&e);
    }
    // Not free: this image's two megapages (`linker.ld`). The device tree is free once this returns: everything boot
    // needs from it is in `p`, and nothing reads it again. Keeping it would split RAM where the firmware put it (EDK2
    // puts it 64 MiB in).
    if let Err(e) = p.reserve(Region { base: kernel_base() as u64, size: 2 * mega }) {
        refuse(&e);
    }
    let Some(free) = p.largest_free(mega) else { refuse(&PlatformError::NoMemory) };
    // The kernel reaches general memory through its direct map, which covers at most 16 GiB: no more is handed out.
    let span = (free.size as usize).min(lantern_hal::RISCV64_DIRECT_MAP_MAX_SPAN);
    if !lantern_hal::riscv64_set_direct_map(free.base as usize, span) {
        refuse(&"general memory the direct map can't cover");
    }
    if span < free.size as usize {
        crate::println!("boot: using {} MiB of {} MiB free: the direct map covers at most 16 GiB", span >> 20, free.size >> 20);
    }
    crate::pmm::set(free.base as usize, free.base as usize + span);
    for ram in p.ram() {
        crate::println!("boot: RAM {:#x}..{:#x}", ram.base, ram.end());
    }
    crate::println!(
        "boot: hart {hartid}, running at {:#x}, timer {} Hz, console {:#x}, {} reserved, general memory {:#x}..{:#x}, DMA {}",
        kernel_base(),
        p.timebase_hz,
        p.uart.base,
        p.reserved().len(),
        free.base,
        free.base as usize + span,
        if dma_uncached { "uncached" } else { "cached (coherent)" }
    );
    // SAFETY: the one write, before any reader.
    unsafe { *PLATFORM.0.get() = Some(p) };
    get()
}

/// The EFI loader's hand-off (`lantern-boot/efi-loader`'s `HANDOFF_MAGIC`), which this must match: `b"LNTNEFI1"`.
#[cfg(target_arch = "riscv64")]
const HANDOFF_MAGIC: u64 = u64::from_le_bytes(*b"LNTNEFI1");
/// The most ranges its table holds: one page, less its count.
#[cfg(target_arch = "riscv64")]
const HANDOFF_MAX: u64 = 255;

/// Reserves every range in the EFI loader's table, if `a2` held its magic: memory the firmware's map says isn't free
/// once boot services are gone. A table that isn't wholly inside RAM, or claims more than a page holds, is refused.
#[cfg(target_arch = "riscv64")]
fn reserve_firmware_memory(p: &mut Platform) -> Result<(), PlatformError> {
    unsafe extern "C" {
        static lantern_boot_handoff: [u64; 2];
    }
    // SAFETY: written once by `entry.rs`, before `boot_main`, and never again.
    let [magic, table] = unsafe { core::ptr::read_volatile(&raw const lantern_boot_handoff) };
    if magic != HANDOFF_MAGIC {
        return Ok(());
    }
    let page = Region { base: table, size: 4096 };
    if table % 4096 != 0 || !p.ram().iter().any(|r| r.base <= page.base && page.end() <= r.end()) {
        return Err(PlatformError::BadHandoff);
    }
    let words = table as *const u64;
    // SAFETY: a page inside RAM, which the loader filled and nothing has touched since: boot hands out no memory before
    // this runs.
    let count = unsafe { core::ptr::read_volatile(words) };
    if count > HANDOFF_MAX {
        return Err(PlatformError::BadHandoff);
    }
    crate::println!("boot: the firmware keeps {count} ranges");
    for i in 0..count as usize {
        // SAFETY: as above; `1 + 2 * i + 1 < 512`.
        let (base, size) = unsafe { (core::ptr::read_volatile(words.add(1 + 2 * i)), core::ptr::read_volatile(words.add(2 + 2 * i))) };
        p.reserve(Region { base, size })?;
    }
    Ok(())
}

/// Where this image runs: `_start`'s megapage.
#[cfg(target_arch = "riscv64")]
pub fn kernel_base() -> usize {
    unsafe extern "C" {
        fn _start();
    }
    _start as *const () as usize & !(lantern_hal::RISCV64_MEGAPAGE_SIZE - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fdt::tests::{fixture, Builder};

    #[test]
    fn qemu_virt_is_read_from_its_tree() {
        let p = Platform::parse(&fixture("qemu-virt.dtb"), 0).unwrap();
        assert_eq!(p.timebase_hz, 10_000_000);
        // QEMU's default CPU: Zicbom but not Svpbmt; its devices are coherent.
        assert!(!p.dma_noncoherent && !p.svpbmt && p.zicbom);
        assert_eq!(p.uart, Uart { base: 0x1000_0000, size: 0x100, reg_shift: 0, io_width: 1, irq: 10, xscale: false });
        assert_eq!(p.intc, Intc::Plic { base: 0x0c00_0000, size: 0x60_0000, context: 1, lines: 96 });
        assert_eq!(p.ram(), &[Region { base: 0x8000_0000, size: 256 << 20 }]);
        let pci = p.pci.unwrap();
        assert_eq!((pci.ecam, pci.bus_first, pci.bus_last), (Region { base: 0x3000_0000, size: 0x1000_0000 }, 0, 255));
        assert_eq!(pci.mem32, Some(Window { cpu: 0x4000_0000, pci: 0x4000_0000, size: 0x4000_0000 }));
        assert_eq!(pci.mem64, Some(Window { cpu: 0x4_0000_0000, pci: 0x4_0000_0000, size: 0x4_0000_0000 }));
        // QEMU's swizzle: device 0's INTA# is line 32, device 1's is 33, device 1's INTB# is 34.
        assert_eq!(pci.intx_line(0, 0, 0, 1), Some(0x20));
        assert_eq!(pci.intx_line(0, 1, 0, 1), Some(0x21));
        assert_eq!(pci.intx_line(0, 1, 0, 2), Some(0x22));
        assert_eq!(pci.intx_line(0, 4, 0, 1), Some(0x20), "the mask folds device 4 onto device 0");
        assert_eq!(pci.intx_line(0, 0, 0, 5), None);
        // Eight slots, lowest first, lines 1 to 8: what boot used to assume.
        let v = p.virtio();
        assert_eq!(v.len(), 8);
        for (i, d) in v.iter().enumerate() {
            assert_eq!((d.base, d.irq), (0x1000_1000 + 0x1000 * i as u64, 1 + i as u32));
        }
    }

    #[test]
    fn qemu_aia_picks_the_supervisor_controllers_not_the_machine_ones() {
        let p = Platform::parse(&fixture("qemu-virt-aia.dtb"), 0).unwrap();
        assert_eq!(
            p.intc,
            Intc::Aia {
                aplic_base: 0x0d00_0000,
                aplic_size: 0x8000,
                sources: 96,
                hart_index: 0,
                imsic_file: 0x2800_0000,
                ids: 255
            }
        );
        assert_eq!(p.virtio().len(), 8, "virtio goes to the supervisor APLIC");
        // The APLIC's specifiers are two cells: the map is read at its own cell counts.
        let pci = p.pci.unwrap();
        assert_eq!((pci.intx_line(0, 0, 0, 1), pci.intx_line(0, 3, 0, 4)), (Some(0x20), Some(0x22)));
        assert_eq!(p.virtio()[0].irq, 1);
    }

    #[test]
    fn the_k3_pico_itx_is_read_from_its_tree() {
        let dtb = fixture("k3-pico-itx.dtb");
        let p = Platform::parse(&dtb, 0).unwrap();
        assert_eq!(p.timebase_hz, 24_000_000);
        // The K3's SoC bus doesn't snoop, and its cores have what keeps DMA coherent anyway.
        assert!(p.dma_noncoherent && p.svpbmt && p.zicbom);
        assert_eq!(p.cbom_block, 64);
        assert_eq!(p.uart, Uart { base: 0xd401_7000, size: 0x100, reg_shift: 2, io_width: 4, irq: 42, xscale: true });
        let Intc::Aia { aplic_base, sources, hart_index, imsic_file, ids, .. } = p.intc else { panic!("{:?}", p.intc) };
        assert_eq!((aplic_base, sources, hart_index, imsic_file, ids), (0xe080_4000, 512, 0, 0xe040_0000, 511));
        assert_eq!(p.ram(), &[Region { base: 0x1_0200_0000, size: 0x1_fe00_0000 }]);
        assert!(!p.reserved().is_empty());
        assert!(p.virtio().is_empty());
        assert!(p.pci.is_none(), "the K3's PCIe hosts are DesignWare ones, not ECAM-generic");
        // Any hart can boot: hart 3's file is three 256 KiB strides on (6 guest-index bits).
        let p3 = Platform::parse(&dtb, 3).unwrap();
        let Intc::Aia { hart_index, imsic_file, .. } = p3.intc else { panic!() };
        assert_eq!((hart_index, imsic_file), (3, 0xe040_0000 + 3 * 0x4_0000));
        assert_eq!(Platform::parse(&dtb, 40).unwrap_err(), PlatformError::BootHartNotFound);
        // The free RAM is all of it: the K3's reservations sit below RAM, in SRAM and the real-time cores' memory.
        assert_eq!(p.largest_free(2 << 20), Some(Region { base: 0x1_0200_0000, size: 0x1_fe00_0000 }));
    }

    #[test]
    fn free_memory_steps_around_reservations_and_aligns_inward() {
        let mut p = Platform::parse(&fixture("qemu-virt.dtb"), 0).unwrap();
        p.reserve(Region { base: 0x8000_0000, size: 0x20_0000 }).unwrap(); // firmware
        p.reserve(Region { base: 0x8020_0000, size: 0x40_0000 }).unwrap(); // the kernel
        p.reserve(Region { base: 0x8f00_0000, size: 0x1_0000 }).unwrap(); // the device tree
        let mega = 2 << 20;
        assert_eq!(p.largest_free(mega), Some(Region { base: 0x8060_0000, size: 0x8f00_0000 - 0x8060_0000 }));
        p.reserve(Region { base: 0x8100_0001, size: 1 }).unwrap();
        // Two runs now: the first megapage-trimmed run, 0x8060_0000..0x8100_0000, and 0x8120_0000..0x8f00_0000.
        assert_eq!(p.largest_free(mega), Some(Region { base: 0x8120_0000, size: 0x8f00_0000 - 0x8120_0000 }));
    }

    fn minimal(stdout: &[u8], compatible: &[u8]) -> Vec<u8> {
        let mut b = Builder::new();
        b.begin(b"").u32(b"#address-cells", 2).u32(b"#size-cells", 2);
        b.begin(b"chosen").prop(b"stdout-path", stdout).end();
        b.begin(b"cpus").u32(b"#address-cells", 1).u32(b"#size-cells", 0).u32(b"timebase-frequency", 1_000_000);
        b.begin(b"cpu@0").prop(b"device_type", b"cpu\0").u32(b"reg", 0);
        b.begin(b"interrupt-controller").prop(b"compatible", b"riscv,cpu-intc\0").u32(b"phandle", 1).end();
        b.end().end();
        b.begin(b"memory@80000000").prop(b"device_type", b"memory\0").cells(b"reg", &[0, 0x8000_0000, 0, 0x100_0000]).end();
        b.begin(b"plic@c000000").prop(b"compatible", b"riscv,plic0\0").u32(b"phandle", 2).u32(b"riscv,ndev", 31);
        b.cells(b"reg", &[0, 0xc00_0000, 0, 0x60_0000]).cells(b"interrupts-extended", &[1, 11, 1, 9]).end();
        b.begin(b"serial@10000000").prop(b"compatible", compatible).cells(b"reg", &[0, 0x1000_0000, 0, 0x100]);
        b.u32(b"interrupt-parent", 2).u32(b"interrupts", 10).end();
        b.end().build()
    }

    #[test]
    fn what_cant_be_used_is_refused_not_guessed() {
        assert!(Platform::parse(&minimal(b"/serial@10000000:115200\0", b"ns16550a\0"), 0).is_ok());
        assert_eq!(
            Platform::parse(&minimal(b"/serial@10000000\0", b"arm,pl011\0"), 0).unwrap_err(),
            PlatformError::ConsoleUnsupported
        );
        assert_eq!(Platform::parse(&minimal(b"serial9\0", b"ns16550a\0"), 0).unwrap_err(), PlatformError::NoConsole);
        assert_eq!(
            Platform::parse(&minimal(b"/serial@10000000\0", b"ns16550a\0"), 1).unwrap_err(),
            PlatformError::BootHartNotFound
        );
    }
}
