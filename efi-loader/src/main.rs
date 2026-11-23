//! `lantern-efi-loader` — [RFC-0032](../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)'s EFI loader, run by
//! the firmware as `\EFI\BOOT\BOOTRISCV64.EFI` from the disk's EFI System Partition.
//!
//! 1. Reads `\LANTERN\BOOT.ELF` from the partition it was loaded from.
//! 2. Claims the kernel's range (`lantern_efi_loader::KERNEL_BASE`, 4 MiB) from the firmware, and places the image there
//!    (`plan`, `place`).
//! 3. Finds the device tree in the firmware's configuration table, and the boot hart through the RISC-V boot protocol.
//! 4. Leaves UEFI (`ExitBootServices`), masks interrupts, turns paging off, makes the copied code visible to instruction
//!    fetch, and jumps to the image's entry with `a0` = hart and `a1` = device tree: what OpenSBI's jump firmware gives the
//!    kernel. The kernel can't tell the difference.
//!
//! **It verifies nothing**: secure boot is Phase 4 (RFC-0023's checklist). It says what failed on the firmware's console,
//! and returns to the firmware, before it has left UEFI; after that, nothing can fail.

#![no_std]
#![no_main]

use core::ffi::c_void;

use lantern_efi_loader::{
    aligned_base, device_tree_size, lowest_fit, place, plan, reserved_ranges, HANDOFF_MAGIC, KERNEL_ALIGN, KERNEL_BASE,
    KERNEL_SIZE, MAX_RESERVED,
};
use r_efi::efi;
use r_efi::protocols::{file, loaded_image, simple_file_system};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// `RISCV_EFI_BOOT_PROTOCOL`: which hart the firmware booted on.
const RISCV_BOOT_PROTOCOL_GUID: efi::Guid =
    efi::Guid::from_fields(0xccd15fec, 0x6f73, 0x4eec, 0x83, 0x95, &[0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf]);

#[repr(C)]
struct RiscvBootProtocol {
    revision: u64,
    get_boot_hartid: extern "efiapi" fn(*mut RiscvBootProtocol, *mut usize) -> efi::Status,
}

const BOOT_IMAGE: &str = "\\LANTERN\\BOOT.ELF";

/// What the loader says, by stage. A table of references, so each one is an absolute address the firmware must relocate:
/// a PE image whose base relocations were wrong would print garbage, or fault, here, at the start, rather than hide the
/// fault until some other pointer matters.
static SAY: [&str; 2] = ["\r\nLantern EFI loader: reading \\LANTERN\\BOOT.ELF\r\n", "Lantern EFI loader: starting LanternOS\r\n"];
const SAY_READING: usize = 0;
const SAY_STARTING: usize = 1;
const PAGE: usize = 4096;

struct Firmware {
    image: efi::Handle,
    st: *mut efi::SystemTable,
}

impl Firmware {
    fn say(&self, text: &str) {
        let mut buf = [0u16; 160];
        for (n, c) in text.encode_utf16().take(buf.len() - 1).enumerate() {
            buf[n] = c;
        }
        // SAFETY: the firmware's tables are valid until ExitBootServices, and this runs before it.
        unsafe {
            let out = (*self.st).con_out;
            ((*out).output_string)(out, buf.as_mut_ptr());
        }
    }

    fn bs(&self) -> &efi::BootServices {
        // SAFETY: as `say`.
        unsafe { &*(*self.st).boot_services }
    }

    fn protocol<T>(&self, handle: efi::Handle, guid: &efi::Guid) -> Result<*mut T, &'static str> {
        let mut guid = *guid;
        let mut out = core::ptr::null_mut();
        let status = (self.bs().handle_protocol)(handle, &mut guid, &mut out);
        if status.is_error() || out.is_null() {
            return Err("a protocol the loader needs is missing");
        }
        Ok(out as *mut T)
    }

    /// `\LANTERN\BOOT.ELF`'s bytes, in pages the firmware allocated.
    fn read_boot_image(&self) -> Result<&'static [u8], &'static str> {
        let loaded: *mut loaded_image::Protocol = self.protocol(self.image, &loaded_image::PROTOCOL_GUID)?;
        // SAFETY: the firmware's own protocol structures, valid until ExitBootServices.
        let device = unsafe { (*loaded).device_handle };
        let fs: *mut simple_file_system::Protocol = self.protocol(device, &simple_file_system::PROTOCOL_GUID)?;
        let mut root: *mut file::Protocol = core::ptr::null_mut();
        // SAFETY: as above; each call is the protocol's own function on its own structure.
        unsafe {
            if ((*fs).open_volume)(fs, &mut root).is_error() {
                return Err("the boot partition can't be opened");
            }
            let mut name = [0u16; 32];
            for (i, c) in BOOT_IMAGE.encode_utf16().enumerate() {
                name[i] = c;
            }
            let mut f: *mut file::Protocol = core::ptr::null_mut();
            if ((*root).open)(root, &mut f, name.as_mut_ptr(), file::MODE_READ, 0).is_error() {
                return Err("\\LANTERN\\BOOT.ELF isn't on the boot partition");
            }
            let mut size = 0u64;
            if ((*f).set_position)(f, u64::MAX).is_error() || ((*f).get_position)(f, &mut size).is_error() || ((*f).set_position)(f, 0).is_error() {
                return Err("the boot image's size can't be read");
            }
            let pages = (size as usize).div_ceil(PAGE);
            let mut at: efi::PhysicalAddress = 0;
            if (self.bs().allocate_pages)(efi::ALLOCATE_ANY_PAGES, efi::LOADER_DATA, pages, &mut at).is_error() {
                return Err("no memory for the boot image");
            }
            let mut read = size as usize;
            if ((*f).read)(f, &mut read, at as *mut c_void).is_error() || read != size as usize {
                return Err("the boot image can't be read");
            }
            ((*f).close)(f);
            ((*root).close)(root);
            Ok(core::slice::from_raw_parts(at as *const u8, size as usize))
        }
    }

    /// The firmware's device tree, copied into pages the loader owns (RFC-0039). The firmware's own copy may be in
    /// memory it reclaims at `ExitBootServices`, as EDK2's is: the kernel would find it overwritten.
    fn device_tree(&self) -> Result<usize, &'static str> {
        // SAFETY: as `say`: the configuration table and its length are the firmware's.
        let tables = unsafe { core::slice::from_raw_parts((*self.st).configuration_table, (*self.st).number_of_table_entries) };
        let theirs = tables
            .iter()
            .find(|t| t.vendor_guid == efi::DTB_TABLE_GUID)
            .map(|t| t.vendor_table as *const u8)
            .ok_or("the firmware gave no device tree")?;
        let mut head = [0u8; 8];
        // SAFETY: the firmware's table points at its device tree, valid until ExitBootServices; its header is 40 bytes.
        unsafe { core::ptr::copy_nonoverlapping(theirs, head.as_mut_ptr(), 8) };
        let size = device_tree_size(head).ok_or("the firmware's device tree isn't one")?;
        let mut at: efi::PhysicalAddress = 0;
        if (self.bs().allocate_pages)(efi::ALLOCATE_ANY_PAGES, efi::LOADER_DATA, size.div_ceil(PAGE), &mut at).is_error() {
            return Err("no memory for the device tree");
        }
        // SAFETY: `size` bytes of the firmware's tree, into `size.div_ceil(PAGE)` pages just allocated, which don't overlap it.
        unsafe { core::ptr::copy_nonoverlapping(theirs, at as *mut u8, size) };
        Ok(at as usize)
    }

    fn boot_hart(&self) -> usize {
        let mut guid = RISCV_BOOT_PROTOCOL_GUID;
        let mut protocol: *mut c_void = core::ptr::null_mut();
        let status = (self.bs().locate_protocol)(&mut guid, core::ptr::null_mut(), &mut protocol);
        if status.is_error() || protocol.is_null() {
            return 0;
        }
        let protocol = protocol as *mut RiscvBootProtocol;
        let mut hart = 0;
        // SAFETY: the firmware's protocol structure and its own function.
        match unsafe { ((*protocol).get_boot_hartid)(protocol, &mut hart) } {
            s if s.is_error() => 0,
            _ => hart,
        }
    }

    /// Leaves UEFI. The memory map's key changes whenever the firmware allocates, so it's fetched just before.
    /// [`lowest_fit`] over the firmware's conventional memory now.
    fn lowest_free_kernel_range(&self) -> Option<u64> {
        let mut buf = [0u8; 16384];
        let (mut size, mut key, mut desc_size, mut version) = (buf.len(), 0usize, 0usize, 0u32);
        let map = buf.as_mut_ptr() as *mut efi::MemoryDescriptor;
        if (self.bs().get_memory_map)(&mut size, map, &mut key, &mut desc_size, &mut version).is_error()
            || desc_size < core::mem::size_of::<efi::MemoryDescriptor>()
        {
            return None;
        }
        let free = (0..size / desc_size).filter_map(|i| {
            // SAFETY: the firmware wrote `size` bytes of descriptors, `desc_size` apart, into `buf`; each is read unaligned.
            let d = unsafe { core::ptr::read_unaligned(buf.as_ptr().add(i * desc_size) as *const efi::MemoryDescriptor) };
            (d.r#type == efi::CONVENTIONAL_MEMORY).then_some((d.physical_start, d.number_of_pages.checked_mul(PAGE as u64)?))
        });
        lowest_fit(free)
    }

    /// Leaves boot services, first writing into `table` (a page the loader owns: a count, then `(base, size)` pairs)
    /// what the memory map it leaves with says the kernel must not use.
    fn exit(&self, table: &mut [u64; 512]) -> Result<(), &'static str> {
        let mut buf = [0u8; 16384];
        for _ in 0..2 {
            let (mut size, mut key, mut desc_size, mut version) = (buf.len(), 0usize, 0usize, 0u32);
            let map = buf.as_mut_ptr() as *mut efi::MemoryDescriptor;
            if (self.bs().get_memory_map)(&mut size, map, &mut key, &mut desc_size, &mut version).is_error()
                || desc_size < core::mem::size_of::<efi::MemoryDescriptor>()
            {
                return Err("the memory map can't be read");
            }
            let descriptors = (0..size / desc_size).map(|i| {
                // SAFETY: the firmware wrote `size` bytes of descriptors, `desc_size` apart, into `buf`; read unaligned.
                let d = unsafe { core::ptr::read_unaligned(buf.as_ptr().add(i * desc_size) as *const efi::MemoryDescriptor) };
                (d.r#type, d.physical_start, d.number_of_pages)
            });
            let mut ranges = [(0u64, 0u64); MAX_RESERVED];
            // Writing into a page already allocated doesn't change the map, so `key` stays good.
            let n = reserved_ranges(descriptors, &mut ranges).ok_or("the firmware reserves too much to hand over")?;
            table[0] = n as u64;
            for (k, &(base, len)) in ranges[..n].iter().enumerate() {
                (table[1 + 2 * k], table[2 + 2 * k]) = (base, len);
            }
            if !(self.bs().exit_boot_services)(self.image, key).is_error() {
                return Ok(());
            }
        }
        Err("the firmware wouldn't let go")
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: efi::Handle, st: *mut efi::SystemTable) -> efi::Status {
    let firmware = Firmware { image, st };
    firmware.say(SAY[core::hint::black_box(SAY_READING)]);
    match boot(&firmware) {
        Err(why) => {
            firmware.say("Lantern EFI loader: ");
            firmware.say(why);
            firmware.say("\r\n");
            efi::Status::LOAD_ERROR
        }
        Ok(never) => match never {},
    }
}

enum Never {}

fn boot(firmware: &Firmware) -> Result<Never, &'static str> {
    let elf = firmware.read_boot_image()?;
    let (entry, copies) = plan(elf).map_err(|_| "the boot image isn't one this loader can place")?;
    // The lowest megapage-aligned room in the firmware's free memory (RFC-0039): RAM is wherever the machine has it,
    // and taking the bottom keeps what's above it one run for the kernel. If the firmware won't give exactly that, any
    // room it has.
    let lowest = firmware.lowest_free_kernel_range().filter(|_| !cfg!(feature = "place-high")).filter(|&at| {
        let mut got = at;
        !(firmware.bs().allocate_pages)(efi::ALLOCATE_ADDRESS, efi::LOADER_DATA, KERNEL_SIZE as usize / PAGE, &mut got).is_error()
    });
    let base = match lowest {
        Some(at) => at,
        None => {
            let mut at: efi::PhysicalAddress = 0;
            let pages = (KERNEL_SIZE + KERNEL_ALIGN) as usize / PAGE;
            if (firmware.bs().allocate_pages)(efi::ALLOCATE_ANY_PAGES, efi::LOADER_DATA, pages, &mut at).is_error() {
                return Err("no memory for the kernel");
            }
            aligned_base(at).ok_or("no memory for the kernel")?
        }
    };
    // SAFETY: the firmware just gave the loader a range holding `[base, base + KERNEL_SIZE)`.
    let kernel = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, KERNEL_SIZE as usize) };
    place(elf, &copies, kernel);
    let entry = base + (entry - KERNEL_BASE);
    let dtb = firmware.device_tree()?;
    let hart = firmware.boot_hart();
    // The reserved-range table's page, allocated now: allocating after the last memory map would change it.
    let mut table_at: efi::PhysicalAddress = 0;
    if (firmware.bs().allocate_pages)(efi::ALLOCATE_ANY_PAGES, efi::LOADER_DATA, 1, &mut table_at).is_error() {
        return Err("no memory for the memory map's hand-off");
    }
    // SAFETY: a page just allocated to the loader, page-aligned, so aligned for `u64`.
    let table = unsafe { &mut *(table_at as *mut [u64; 512]) };
    firmware.say(SAY[core::hint::black_box(SAY_STARTING)]);
    firmware.exit(table)?;
    // SAFETY: UEFI is gone and nothing else runs. Interrupts are masked and paging turned off before the jump, so the
    // kernel starts as it does from OpenSBI: in S-mode, with the MMU off, `a0` the hart and `a1` the device tree; and `a2`
    // and `a3` the memory map's hand-off (RFC-0039). The
    // `fence.i` makes the copied code visible to instruction fetch.
    unsafe {
        core::arch::asm!(
            "csrci sstatus, 2",
            "csrw sie, zero",
            "csrw satp, zero",
            "sfence.vma",
            "fence.i",
            "jr {entry}",
            entry = in(reg) entry,
            in("a0") hart,
            in("a1") dtb,
            in("a2") HANDOFF_MAGIC,
            in("a3") table_at,
            options(noreturn)
        )
    }
}
