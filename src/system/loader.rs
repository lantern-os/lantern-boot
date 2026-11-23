//! Boots [RFC-0026](../../../lantern-rfcs/rfcs/0026-trusted-path-and-consent.md)'s **interactive system image**: the first
//! boot image that is a system rather than a demo. A person decides each grant at a console only the shell can reach, and
//! since [RFC-0029](../../../lantern-rfcs/rfcs/0029-a-confined-launcher.md), runs the apps they choose there.
//!
//! Thirteen confined programs, and no app until a person asks:
//!
//! - **`lantern-shell/shell/`** holds the UART's 4 KiB page and its `IrqHandler`, so it is the only program that can
//!   read or write the console. It also holds the binder's control capability, the audit log's read-only one, one
//!   capability per answer to the binder's answer notification, and the launcher's notification under `COMMAND`. It waits
//!   on one notification, whose badge bits are its inputs: the console, the binder, the launcher's replies and each app's
//!   end, and the policy store's panic report.
//! - **`lantern-shell/launcher/`** builds each app's process from the package set when the shell asks, in one of 4 app
//!   slots carved from an `Untyped` of 4 × 18 MiB that only it holds, and reclaims it when it ends. It holds each slot's
//!   service channels, the runtime's ELF and the package set, and the binder's endpoint under the registration badge and
//!   each slot's badge, all minted here.
//! - **`lantern-shell/launch-binder/`**, launched `WITH_CONSENT` and `WITH_LAUNCHER`: it verifies every package in the
//!   set itself, and decides each app's requests, within its policy, by asking the person.
//! - **`lantern-shell/policy-store/`**, which keeps remembered decisions and the audit log on the disk's policy partition
//!   ([RFC-0032](../../../lantern-rfcs/rfcs/0032-installing-a-bootable-disk.md)): a machine booting through UEFI gives
//!   its flash to the firmware. The image needs at least `-m 256M`, for the apps' memory.
//! - **`keystore-service`**, in its system profile: the apps' signing key, granted only over the binder's `GRANT`, and the
//!   store's sealing key, granted once to its first caller, the store. One channel per app slot, and the store's.
//! - **`store-service`**, sealing each block through the keystore, with one channel per app slot, and keeping its files
//!   on the disk ([RFC-0031](../../../lantern-rfcs/rfcs/0031-storage-a-block-driver-and-the-store-on-disk.md)).
//! - **`blk-driver`**, the virtio-blk device's driver: its register page, its line, and a DMA `Untyped`. Trusted with all
//!   memory, since QEMU `virt` has no IOMMU; it parses nothing from the disk, and serves only the volume.
//! - **`volume`**, which reads the disk's GPT and serves each client its own partition: the packages, read-only, to the
//!   launcher and the binder, which each read and verify them; the store's to the store; the model's, read-only, to the
//!   inference service.
//! - **`inference-service`** ([RFC-0034](../../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md)):
//!   the language model, read from the disk's model partition into its heap and checked against the digest it was built
//!   with, served only to the binder's grants, each call recorded first. One channel per app slot. Its 24 MiB heap fits in
//!   the image's `-m 256M` beside the apps' memory.
//! - **`rng-driver`**, **`net-driver`**, **`net`** and **`wallet`**
//!   ([RFC-0035](../../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)): randomness, a network card, a UDP stack
//!   that holds no key, and the wallet, which holds every identity's key and presents each app's pairwise identity to a
//!   peer over an encrypted session. Without `-device virtio-rng-device` and
//!   `-netdev user,id=net -device virtio-net-device,netdev=net`, the drivers refuse every request, and the wallet every
//!   session; nothing else changes.
//! - **`archiver`** ([RFC-0038](../../../lantern-rfcs/rfcs/0038-signed-models-and-kept-audit-history.md)): keeps audit
//!   history before the policy store retires it, sealed under its own keystore key, in the disk's archive partition, and
//!   reads it back for the shell. The policy store wakes it, without blocking, while a full sector waits.
//!
//! **This image needs a disk** from `lantern-mkdisk`, as virtio-blk on virtio-mmio, modern:
//! `-global virtio-mmio.force-legacy=false -drive if=none,format=raw,file=<disk.img>,id=disk -device virtio-blk-device,drive=disk`.
//!
//! Each app slot's channel Frames are made here and mapped into the services for good; the launcher gets their
//! capabilities and nothing else of the services', maps a slot's channel into its app, and clears it between apps. So a
//! service's shared memory never comes from an app's (RFC-0030).
//!
//! **The boot code and the kernel stay off the console once the shell runs** (ADR-0031): this image's trap handler
//! narrates nothing, and only a panic prints.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const STORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/store-service.elf");
const CONFINED_RUNTIME_ELF: &[u8] = include_bytes!("../../assets/confined-runtime.elf");
const LAUNCH_BINDER_ELF: &[u8] = include_bytes!("../../assets/launch-binder.elf");
const LAUNCHER_ELF: &[u8] = include_bytes!("../../assets/launcher.elf");
#[cfg(not(feature = "audit-ring-test"))]
const POLICY_STORE_ELF: &[u8] = include_bytes!("../../assets/policy-store.elf");
/// RFC-0038's console matrix: the policy store and archiver built with `small-audit-sectors`, so the audit ring fills,
/// exports and wraps within a test. Never in a real image.
#[cfg(feature = "audit-ring-test")]
const POLICY_STORE_ELF: &[u8] = include_bytes!("../../assets/policy-store-small-audit.elf");
const SHELL_ELF: &[u8] = include_bytes!("../../assets/shell.elf");
const BLK_DRIVER_ELF: &[u8] = include_bytes!("../../assets/blk-driver.elf");
/// RFC-0039: the NVMe driver, used in the virtio-blk driver's place when the machine has an NVMe controller.
const NVME_DRIVER_ELF: &[u8] = include_bytes!("../../assets/nvme-driver.elf");
/// `nvme-driver/src/main.rs`'s `ARG0_INTERRUPT`: it has an `IrqHandler`.
const NVME_ARG0_INTERRUPT: usize = 1;
const VOLUME_ELF: &[u8] = include_bytes!("../../assets/volume.elf");
const INFERENCE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/inference-service.elf");
const RNG_DRIVER_ELF: &[u8] = include_bytes!("../../assets/rng-driver.elf");
const NET_DRIVER_ELF: &[u8] = include_bytes!("../../assets/net-driver.elf");
const NET_ELF: &[u8] = include_bytes!("../../assets/net.elf");
const WALLET_ELF: &[u8] = include_bytes!("../../assets/wallet.elf");
#[cfg(not(feature = "audit-ring-test"))]
const ARCHIVER_ELF: &[u8] = include_bytes!("../../assets/archiver.elf");
#[cfg(feature = "audit-ring-test")]
const ARCHIVER_ELF: &[u8] = include_bytes!("../../assets/archiver-small-audit.elf");

/// `blk-driver/src/main.rs`'s and `volume/src/main.rs`'s slots, and their channels.
const DRIVER_ENDPOINT: CPtr = 1;
const DRIVER_IRQ: CPtr = 2;
const DRIVER_NOTIFY: CPtr = 3;
const DRIVER_DMA: CPtr = 4;
const DRIVER_SELF_VSPACE: CPtr = 5;
const DRIVER_FAILURE: CPtr = 6;
const DRIVER_REGS_VADDR: usize = 0x9500_0000;
const DRIVER_CHANNEL_VADDR: usize = 0x9000_0000;
const DMA_BYTES: usize = lantern_hal::RISCV64_MEGAPAGE_SIZE;
const VOLUME_ENDPOINT: CPtr = 1;
const VOLUME_DRIVER: CPtr = 2;
const VOLUME_FAILURE: CPtr = 3;
const VOLUME_DRIVER_VADDR: usize = 0x9000_0000;
const VOLUME_CLIENT_VADDR: usize = 0x9001_0000;
/// `lantern_abi::block::badge`: the volume's three clients, each with its own channel, and the driver's one.
const VOLUME_BADGE_LAUNCHER: u64 = 1;
const VOLUME_BADGE_STORE: u64 = 2;
const VOLUME_BADGE_BINDER: u64 = 3;
const VOLUME_BADGE_POLICY: u64 = 4;
const VOLUME_BADGE_MODELS: u64 = 5;
const VOLUME_BADGE_WALLET: u64 = 6;
/// `policy-store`'s `ON_DISK`, its volume slot and channel, and the heap megapage it mirrors its partition in.
const POLICY_STORE_ON_DISK: usize = 1 << 20;
const POLICY_STORE_VOLUME: CPtr = 5;
const POLICY_STORE_VOLUME_VADDR: usize = 0x9001_0000;
const POLICY_STORE_MIRROR_MEGAPAGES: usize = 1;
const DRIVER_BADGE_VOLUME: u64 = 1;
/// Where each client maps its channel to the volume, and the Frames the launcher and the binder read packages into.
const LAUNCHER_VOLUME: CPtr = 66;
const LAUNCHER_SET_FRAMES: CPtr = 67;
const BINDER_VOLUME: CPtr = 16;
const BINDER_SELF_VSPACE: CPtr = 17;
const BINDER_SET_FRAMES: CPtr = 20;
const SET_FRAMES: usize = 4;
const CLIENT_VOLUME_VADDR: usize = 0x9001_0000;
const STORE_VOLUME: CPtr = 6;
const STORE_VOLUME_VADDR: usize = 0x9002_0000;
/// `store-service`'s `ON_DISK`.
const STORE_ON_DISK: usize = 1 << 11;

/// `keystore-service`'s slots, `PROFILE_SYSTEM`, and where its channels are: one per app slot, then the store's.
const KEYSTORE_ENDPOINT_CPTR: CPtr = 1;
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
const ARG0_KEYSTORE_SYSTEM: usize = 2;
const KEYSTORE_CHANNEL_VADDR: usize = 0x9000_0000;
const CHANNEL_STRIDE: usize = 0x1000;
/// `store-service`'s slots and addresses.
const STORE_KS_ENDPOINT_CPTR: CPtr = 1;
const STORE_OWN_ENDPOINT_CPTR: CPtr = 3;
const STORE_SELF_CNODE_CPTR: CPtr = 0;
const ARG0_STORE: usize = 1;
const STORE_KS_FRAME_VADDR: usize = 0x9000_0000;
const STORE_CLIENT_FRAME_VADDR: usize = 0x9001_0000;
/// `inference-service`'s slots, addresses and `arg0` (RFC-0034): its heap holds the model and the engine's buffers.
const INFERENCE_SELF_CNODE: CPtr = 0;
const INFERENCE_ENDPOINT: CPtr = 1;
const INFERENCE_AUDIT: CPtr = 3;
const INFERENCE_VOLUME: CPtr = 4;
const INFERENCE_FAILURE: CPtr = 5;
const INFERENCE_CLIENT_VADDR: usize = 0x9001_0000;
const INFERENCE_VOLUME_VADDR: usize = 0x9002_0000;
/// 12 × 2 MiB: the 17.5 MB model, its 3.5 MB of attention cache and the rest of the engine's buffers, with room to spare.
const INFERENCE_HEAP_MEGAPAGES: usize = 12;
const INFERENCE_ARG0: usize = launch::AUDITED | INFERENCE_HEAP_MEGAPAGES << 16;
/// The binder's slot for the inference service's granter (`launch-binder`'s `INFERENCE_GRANTER_CPTR`).
const BINDER_INFERENCE_GRANTER: CPtr = 18;
/// The launcher's slots for each app slot's channel to the inference service (`launcher`'s `IN_CHANNEL`).
const LAUNCHER_IN_CHANNEL: CPtr = 72;
/// RFC-0034: the store under `provenance::STORE_CONSOLE_BADGE`, the shell's `write`, with its own channel.
const SHELL_STORE_CONSOLE_CPTR: CPtr = 12;
const SHELL_STORE_CONSOLE_VADDR: usize = 0x9002_0000;
const STORE_CONSOLE_BADGE: u64 = launch::GRANTER_BADGE - 2;
const STORE_CONSOLE_FRAME_VADDR: usize = STORE_CLIENT_FRAME_VADDR + APP_SLOTS * CHANNEL_STRIDE;

/// RFC-0035: each driver's slots (as `blk-driver`'s: its endpoint, line, notification, DMA, own VSpace, failure report)
/// and `arg0`'s flag for a device the machine doesn't have.
const D_ENDPOINT: CPtr = 1;
const D_IRQ: CPtr = 2;
const D_NOTIFY: CPtr = 3;
const D_DMA: CPtr = 4;
const D_SELF_VSPACE: CPtr = 5;
const D_FAILURE: CPtr = 6;
const DEVICE_ABSENT: usize = 1;
const VIRTIO_NET: u32 = 1;
const VIRTIO_RNG: u32 = 4;
/// `net`'s slots and addresses.
const N_ENDPOINT: CPtr = 1;
const N_DRIVER: CPtr = 2;
const N_NOTIFY: CPtr = 3;
const N_DEADLINE: CPtr = 4;
const N_TIMER_BIT: CPtr = 5;
const N_FAILURE: CPtr = 6;
const N_DRIVER_VADDR: usize = 0x9000_0000;
const N_CLIENT_VADDR: usize = 0x9001_0000;
/// `lantern_abi::net::driver::BIT_RX` and `BIT_TIMER`, on `net`'s notification.
const NET_BIT_RX: u64 = 1 << 0;
const NET_BIT_TIMER: u64 = 1 << 1;
/// `wallet`'s slots and addresses.
const W_SELF_CNODE: CPtr = 0;
const W_ENDPOINT: CPtr = 1;
const W_AUDIT: CPtr = 3;
const W_VOLUME: CPtr = 4;
const W_RNG: CPtr = 5;
const W_NET: CPtr = 6;
const W_KEYSTORE: CPtr = 7;
const W_FAILURE: CPtr = 9;
const W_CLIENT_VADDR: usize = 0x9001_0000;
const W_VOLUME_VADDR: usize = 0x9002_0000;
const W_NET_VADDR: usize = 0x9003_0000;
const W_KEYSTORE_VADDR: usize = 0x9004_0000;
/// `lantern_abi::identity::KEYSTORE_BADGE` and `READER_BADGE`, and `policy::WALLET_WRITER_BADGE`.
const WALLET_KEYSTORE_BADGE: u64 = launch::GRANTER_BADGE - 1;
const WALLET_READER_BADGE: u64 = launch::GRANTER_BADGE - 1;
const WALLET_WRITER_BADGE: u64 = launch::READER_BADGE - 4;
/// The binder's slot for the wallet's granter, the launcher's for each app slot's channel to it, and the shell's for its
/// reader badge.
const BINDER_WALLET_GRANTER: CPtr = 19;
const LAUNCHER_ID_CHANNEL: CPtr = 76;
const SHELL_WALLET_READER_CPTR: CPtr = 13;
/// The keystore's channel for the wallet, after the app slots' and the store's.
const KEYSTORE_WALLET_CHANNEL: usize = APP_SLOTS + 1;

/// `policy-store`'s panic report.
const POLICY_STORE_FAILURE_CPTR: CPtr = 4;
/// [RFC-0038](../../../lantern-rfcs/rfcs/0038-signed-models-and-kept-audit-history.md): `policy-store`'s flag for an
/// archiver, its slot for waking it, and the page it shares with it.
const POLICY_STORE_WITH_ARCHIVER: usize = 1 << 21;
const POLICY_STORE_ARCHIVER_WAKE: CPtr = 6;
const POLICY_STORE_ARCHIVER_PAGE_VADDR: usize = 0x9002_0000;
/// `lantern-shell/archiver`'s slots and addresses.
const A_ENDPOINT: CPtr = 1;
const A_POLICY: CPtr = 2;
const A_KEYSTORE: CPtr = 3;
const A_VOLUME: CPtr = 5;
const A_FAILURE: CPtr = 6;
const A_POLICY_PAGE_VADDR: usize = 0x9001_0000;
const A_VOLUME_VADDR: usize = 0x9002_0000;
const A_KEYSTORE_VADDR: usize = 0x9003_0000;
/// `lantern_abi::policy::ARCHIVER_BADGE` and `ARCHIVER_WAKE_BADGE`, `lantern_abi::archive::KEYSTORE_BADGE` and
/// `READER_BADGE`, and the volume's `ARCHIVE` badge.
const ARCHIVER_POLICY_BADGE: u64 = launch::READER_BADGE - 5;
const ARCHIVER_WAKE_BADGE: u64 = 2;
const ARCHIVER_KEYSTORE_BADGE: u64 = launch::GRANTER_BADGE - 2;
const ARCHIVER_READER_BADGE: u64 = 1;
const VOLUME_BADGE_ARCHIVE: u64 = 7;
/// The keystore's channel for the archiver, after the wallet's; and the shell's slot for reading the archive.
const KEYSTORE_ARCHIVER_CHANNEL: usize = APP_SLOTS + 2;
const SHELL_ARCHIVE_READER_CPTR: CPtr = 14;
/// `launch-binder`'s own CNode, with a launcher.
const BINDER_SELF_CNODE_CPTR: CPtr = 15;

/// `shell/src/main.rs`'s slots and addresses.
const SHELL_IRQ_CPTR: CPtr = 1;
const SHELL_NOTIFY_CPTR: CPtr = 2;
const SHELL_CONSOLE_BIT_CPTR: CPtr = 3;
const SHELL_CONTROL_CPTR: CPtr = 4;
const SHELL_READER_CPTR: CPtr = 5;
const SHELL_ANSWER_CPTR_BASE: CPtr = 6;
const SHELL_LAUNCHER_CPTR: CPtr = 10;
/// RFC-0033: the store under `lantern_abi::provenance::STORE_READER_BADGE`, sizes and provenance only.
const SHELL_STORE_READER_CPTR: CPtr = 11;
const STORE_READER_BADGE: u64 = launch::GRANTER_BADGE - 1;
const SHELL_UART_VADDR: usize = 0x9500_0000;
const SHELL_LAUNCHER_VADDR: usize = 0x9001_0000;

/// `launcher/src/main.rs`'s slots and addresses.
const LAUNCHER_MEMORY: CPtr = 1;
const LAUNCHER_SELF_CNODE: CPtr = 2;
const LAUNCHER_SELF_VSPACE: CPtr = 3;
const LAUNCHER_NOTIFY: CPtr = 4;
const LAUNCHER_REGISTER: CPtr = 5;
const LAUNCHER_APP_BINDER: CPtr = 6;
const LAUNCHER_SHELL_REPLIED: CPtr = 10;
const LAUNCHER_SHELL_ENDED: CPtr = 11;
const LAUNCHER_SHELL_FAILED: CPtr = 15;
const LAUNCHER_KS_CHANNEL: CPtr = 19;
const LAUNCHER_ST_CHANNEL: CPtr = 23;
const LAUNCHER_HEAP_MEGAPAGES: usize = 1;
const LAUNCHER_RUNTIME_VADDR: usize = 0x8a00_0000;
const LAUNCHER_COMMAND_VADDR: usize = 0x9000_0000;
/// 4 app slots of 18 MiB each (`launcher/src/main.rs`'s `SLOT_BYTES`).
const APP_MEMORY: usize = APP_SLOTS * 9 * lantern_hal::RISCV64_MEGAPAGE_SIZE;
/// `launcher::HOLD`: with boot's `launcher-hold-test` feature only.
const LAUNCHER_HOLD: usize = if cfg!(feature = "launcher-hold-test") { 1 << 63 } else { 0 };

/// `lantern_abi::grant` and `lantern_abi::launcher`'s values.
const APP_SLOTS: usize = 4;
const WITH_LAUNCHER: usize = 1 << 41;
const MANY_CLIENTS: usize = 1 << 10;
const REGISTER_BADGE: u64 = launch::CONTROL_BADGE - 1;
const fn app_badge(app: usize) -> u64 {
    1 + app as u64
}
const LAUNCHER_COMMAND_BIT: u64 = 1 << 0;
const SHELL_REPLIED_BIT: u64 = 1 << 7;
const fn shell_ended_bit(app: usize) -> u64 {
    1 << (8 + app)
}
const fn shell_failed_bit(app: usize) -> u64 {
    1 << (12 + app)
}

/// `lantern_abi::consent::bit`, and `Answer::badge`'s values, in the order the shell holds them.
const BIT_CONSOLE: u64 = 1 << 0;
const BIT_ASK: u64 = 1 << 1;
const BIT_SYSTEM_FAILED: u64 = 1 << 4;
const BIT_ASK_DONE: u64 = 1 << 5;
const BIT_ASK_CANCELLED: u64 = 1 << 6;
/// `lantern_abi::consent::TIMED_OUT`, on the binder's answer notification.
const BIT_TIMED_OUT: u64 = 1 << 4;
const ANSWER_BADGES: [u64; 4] = [1 << 0, 1 << 1, 1 << 2, 1 << 3];

/// The console UART's page and interrupt line, from the device tree (RFC-0039).
fn uart_page() -> usize {
    crate::platform::get().uart.base as usize & !0xfff
}

fn uart_line() -> u16 {
    u16::try_from(crate::platform::get().uart.irq).expect("the console's interrupt line is out of range")
}

/// The shell's `arg0`: the UART's layout, in `lantern_abi::console::UartLayout`'s encoding, which this must match.
fn shell_arg0() -> usize {
    let uart = crate::platform::get().uart;
    (uart.reg_shift as usize & 0b11)
        | ((uart.io_width == 4) as usize) << 2
        | (uart.xscale as usize) << 3
        | (uart.base as usize & 0xfff) << 12
}

/// The machine's disk, and so which driver serves it (RFC-0039).
#[derive(Clone, Copy)]
enum Disk {
    Virtio { paddr: usize, line: u16 },
    Nvme { paddr: usize, size: usize, line: Option<u16> },
}

impl Disk {
    fn line(self) -> Option<u16> {
        match self {
            Disk::Virtio { line, .. } => Some(line),
            Disk::Nvme { line, .. } => line,
        }
    }

    fn elf(self) -> &'static [u8] {
        match self {
            Disk::Virtio { .. } => BLK_DRIVER_ELF,
            Disk::Nvme { .. } => NVME_DRIVER_ELF,
        }
    }

    fn arg0(self) -> usize {
        match self {
            Disk::Nvme { line: Some(_), .. } => NVME_ARG0_INTERRUPT,
            _ => 0,
        }
    }

    fn paddr(self) -> usize {
        match self {
            Disk::Virtio { paddr, .. } | Disk::Nvme { paddr, .. } => paddr,
        }
    }

    /// The register pages its driver maps: virtio-mmio's one, or an NVMe controller's registers and first doorbells.
    fn register_pages(self) -> usize {
        match self {
            Disk::Virtio { .. } => 1,
            Disk::Nvme { size, .. } => 2.min(size / 0x1000),
        }
    }
}

/// # Safety
/// Must be called at most once, before any trap has occurred.
pub unsafe fn run(mem_end: usize) -> ! {
    // SAFETY: forwarded from this function's own contract.
    let state = unsafe { lantern_kernel::state::kernel_state() };
    let root_cnode_idx = state.cnodes.alloc(CNode::empty()).expect("cnode pool exhausted");
    let root = TcbId(state.tcbs.alloc(Tcb::new()).expect("tcb pool exhausted") as u16);
    state.tcbs.get_mut(root.0 as usize).unwrap().cspace = Some(CNodeId(root_cnode_idx as u16));
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(SELF_CNODE_CPTR).unwrap() =
        Capability::CNode(CNodeId(root_cnode_idx as u16));
    let mem_end = mem_end.max(pmm::general_memory_base() + lantern_hal::RISCV64_MEGAPAGE_SIZE)
        & !(lantern_hal::RISCV64_MEGAPAGE_SIZE - 1);
    let untyped = Untyped::with_memory(1000, pmm::general_memory_base(), mem_end - pmm::general_memory_base());
    let untyped_idx = state.untypeds.alloc(untyped).expect("untyped pool exhausted");
    let untyped_cptr: CPtr = 1;
    *state.cnodes.get_mut(root_cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
        Capability::Untyped { id: UntypedId(untyped_idx as u16), rights: Rights::ALL };
    let mut next_slot: CPtr = 2; // slot 0 is SELF_CNODE_CPTR, slot 1 is untyped_cptr.
    let slot = |next_slot: &mut CPtr| {
        let s = *next_slot;
        *next_slot += 1;
        s
    };
    let retype = |state: &mut _, next_slot: &mut CPtr, object| {
        let s = slot(next_slot);
        launch::retype(state, root, untyped_cptr, object, s);
        s
    };
    let mint = |state: &mut _, next_slot: &mut CPtr, src, rights, badge| {
        let s = slot(next_slot);
        launch::mint(state, root, src, s, rights, badge);
        s
    };

    // The keystore, the store, and the binder's granter capability on each (the binder's alone).
    let endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let granter = mint(state, &mut next_slot, endpoint, Rights::WRITE, launch::GRANTER_BADGE);
    let store_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let store_granter = mint(state, &mut next_slot, store_endpoint, Rights::WRITE, launch::GRANTER_BADGE);
    let store_reader = mint(state, &mut next_slot, store_endpoint, Rights::WRITE, STORE_READER_BADGE);
    let store_console = mint(state, &mut next_slot, store_endpoint, Rights::WRITE, STORE_CONSOLE_BADGE);
    // RFC-0034: the inference service, and the binder's granter on it.
    let inference_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let inference_granter = mint(state, &mut next_slot, inference_endpoint, Rights::WRITE, launch::GRANTER_BADGE);
    // RFC-0035: randomness, the network card, the network service and the wallet, and the badges each serves.
    let rng_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let rng_for_wallet = mint(state, &mut next_slot, rng_endpoint, Rights::WRITE, 1);
    let net_driver_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let net_driver_for_net = mint(state, &mut next_slot, net_driver_endpoint, Rights::WRITE, 1);
    let net_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let net_for_wallet = mint(state, &mut next_slot, net_endpoint, Rights::WRITE, 1);
    let wallet_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let wallet_granter = mint(state, &mut next_slot, wallet_endpoint, Rights::WRITE, launch::GRANTER_BADGE);
    let wallet_reader = mint(state, &mut next_slot, wallet_endpoint, Rights::WRITE, WALLET_READER_BADGE);
    // RFC-0031: the driver, its one client's badge, and the volume's three.
    let driver_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let driver_for_volume = mint(state, &mut next_slot, driver_endpoint, Rights::WRITE, DRIVER_BADGE_VOLUME);
    let volume_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let volume_launcher = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_LAUNCHER);
    let volume_store = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_STORE);
    let volume_binder = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_BINDER);
    let volume_policy = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_POLICY);
    let volume_models = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_MODELS);
    let volume_wallet = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_WALLET);
    // RFC-0038: the archiver's endpoint, with the policy store's badge for waking it and the shell's for reading; its badges
    // on the volume, the policy store and the keystore.
    let volume_archive = mint(state, &mut next_slot, volume_endpoint, Rights::WRITE, VOLUME_BADGE_ARCHIVE);
    let archiver_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let archiver_wake = mint(state, &mut next_slot, archiver_endpoint, Rights::WRITE, ARCHIVER_WAKE_BADGE);
    let archiver_reader = mint(state, &mut next_slot, archiver_endpoint, Rights::WRITE, ARCHIVER_READER_BADGE);
    // RFC-0039: the disk is an NVMe controller's, if the machine has one, otherwise a virtio-blk device's.
    let disk = match launch::find_nvme() {
        Some((paddr, size, line)) => Disk::Nvme { paddr, size, line },
        None => {
            let (paddr, line) = launch::find_virtio_blk().expect("no NVMe or virtio-blk disk: this image needs a disk");
            Disk::Virtio { paddr, line }
        }
    };
    let driver_notification = retype(state, &mut next_slot, ObjectType::Notification);
    let driver_notify = mint(state, &mut next_slot, driver_notification, Rights::ALL, 1);
    let driver_irq = slot(&mut next_slot);
    if let Some(line) = disk.line() {
        launch::irq_handler(state, root, line, driver_irq);
    }
    let driver_dma = slot(&mut next_slot);
    launch::dma_untyped(state, root, untyped_cptr, driver_dma, DMA_BYTES);
    // The binder's endpoint: the shell's control badge, the launcher's registration badge, and one per app slot.
    let binder_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let binder_control = mint(state, &mut next_slot, binder_endpoint, Rights::WRITE, launch::CONTROL_BADGE);
    let register = mint(state, &mut next_slot, binder_endpoint, Rights::WRITE, REGISTER_BADGE);
    let app_binder: [CPtr; APP_SLOTS] =
        core::array::from_fn(|app| mint(state, &mut next_slot, binder_endpoint, Rights::WRITE, app_badge(app)));
    // The policy store, and its binder, reader and service-writer badges.
    let policy_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let policy_client = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, 0);
    let policy_reader = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, launch::READER_BADGE);
    let keystore_writer = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, launch::KEYSTORE_WRITER_BADGE);
    let store_writer = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, launch::STORE_WRITER_BADGE);
    let inference_writer = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, launch::INFERENCE_WRITER_BADGE);
    let wallet_writer = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, WALLET_WRITER_BADGE);
    let keystore_for_wallet = mint(state, &mut next_slot, endpoint, Rights::WRITE, WALLET_KEYSTORE_BADGE);
    let policy_archiver = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, ARCHIVER_POLICY_BADGE);
    let keystore_for_archiver = mint(state, &mut next_slot, endpoint, Rights::WRITE, ARCHIVER_KEYSTORE_BADGE);
    // The drivers' devices, lines and DMA memory, if the machine has them; `net`'s notification, where the network card's
    // interrupt goes, and its deadline.
    let rng_device = launch::find_virtio(VIRTIO_RNG);
    let net_device = launch::find_virtio(VIRTIO_NET);
    let rng_notification = retype(state, &mut next_slot, ObjectType::Notification);
    let rng_notify = mint(state, &mut next_slot, rng_notification, Rights::ALL, 1);
    let net_notification = retype(state, &mut next_slot, ObjectType::Notification);
    let net_rx_bit = mint(state, &mut next_slot, net_notification, Rights::WRITE, NET_BIT_RX);
    let net_timer_bit = mint(state, &mut next_slot, net_notification, Rights::WRITE, NET_BIT_TIMER);
    let net_deadline = slot(&mut next_slot);
    launch::deadline(state, root, net_deadline);
    let device = |state: &mut _, next_slot: &mut CPtr, found: Option<(usize, u16)>| -> (CPtr, CPtr) {
        let (irq, dma) = (slot(next_slot), slot(next_slot));
        if let Some((_, line)) = found {
            launch::irq_handler(state, root, line, irq);
            launch::dma_untyped(state, root, untyped_cptr, dma, DMA_BYTES);
        }
        (irq, dma)
    };
    let (rng_irq, rng_dma) = device(state, &mut next_slot, rng_device);
    let (net_irq, net_dma) = device(state, &mut next_slot, net_device);
    // The shell's notification, and one write-only badge for each of its inputs.
    let shell_notify = retype(state, &mut next_slot, ObjectType::Notification);
    let console_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_CONSOLE);
    let ask_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_ASK);
    let system_failed_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_SYSTEM_FAILED);
    let ask_done_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_ASK_DONE);
    let ask_cancelled_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_ASK_CANCELLED);
    let replied_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, SHELL_REPLIED_BIT);
    let ended_bits: [CPtr; APP_SLOTS] =
        core::array::from_fn(|app| mint(state, &mut next_slot, shell_notify, Rights::WRITE, shell_ended_bit(app)));
    let failed_bits: [CPtr; APP_SLOTS] =
        core::array::from_fn(|app| mint(state, &mut next_slot, shell_notify, Rights::WRITE, shell_failed_bit(app)));
    // The binder's answer notification, and one write-only badge per answer, all the shell's.
    let answer = retype(state, &mut next_slot, ObjectType::Notification);
    let answers = ANSWER_BADGES.map(|badge| mint(state, &mut next_slot, answer, Rights::WRITE, badge));
    // RFC-0028: the binder's deadline, bound by the binder to its own answer notification under `TIMED_OUT`.
    let timed_out_bit = mint(state, &mut next_slot, answer, Rights::WRITE, BIT_TIMED_OUT);
    let binder_deadline = slot(&mut next_slot);
    launch::deadline(state, root, binder_deadline);
    let irq = slot(&mut next_slot);
    launch::irq_handler(state, root, uart_line(), irq);
    // The launcher's notification (all of it is the launcher's), the shell's badge on it, and the apps' memory.
    let launcher_notify = retype(state, &mut next_slot, ObjectType::Notification);
    let command_bit = mint(state, &mut next_slot, launcher_notify, Rights::WRITE, LAUNCHER_COMMAND_BIT);
    let app_memory = slot(&mut next_slot);
    launch::retype_untyped(state, root, untyped_cptr, app_memory, APP_MEMORY);
    // Each app slot's channels: made here, from the system's memory, never an app's.
    let small_frame = |state: &mut _, next_slot: &mut CPtr| {
        let s = slot(next_slot);
        launch::retype_frame(state, root, untyped_cptr, ObjectType::FrameSmall, s);
        s
    };
    let ks_channels: [CPtr; APP_SLOTS] = core::array::from_fn(|_| small_frame(state, &mut next_slot));
    let st_channels: [CPtr; APP_SLOTS] = core::array::from_fn(|_| small_frame(state, &mut next_slot));
    let in_channels: [CPtr; APP_SLOTS] = core::array::from_fn(|_| small_frame(state, &mut next_slot));
    let id_channels: [CPtr; APP_SLOTS] = core::array::from_fn(|_| small_frame(state, &mut next_slot));

    let shell_grants = [
        (irq, SHELL_IRQ_CPTR),
        (shell_notify, SHELL_NOTIFY_CPTR),
        (console_bit, SHELL_CONSOLE_BIT_CPTR),
        (binder_control, SHELL_CONTROL_CPTR),
        (policy_reader, SHELL_READER_CPTR),
        (answers[0], SHELL_ANSWER_CPTR_BASE),
        (answers[1], SHELL_ANSWER_CPTR_BASE + 1),
        (answers[2], SHELL_ANSWER_CPTR_BASE + 2),
        (answers[3], SHELL_ANSWER_CPTR_BASE + 3),
        (command_bit, SHELL_LAUNCHER_CPTR),
        (store_reader, SHELL_STORE_READER_CPTR),
        (store_console, SHELL_STORE_CONSOLE_CPTR),
        (wallet_reader, SHELL_WALLET_READER_CPTR),
        (archiver_reader, SHELL_ARCHIVE_READER_CPTR),
    ];
    let mut launcher_grants = [(0, 0); 5 + 7 * APP_SLOTS];
    let fixed = [
        (app_memory, LAUNCHER_MEMORY),
        (launcher_notify, LAUNCHER_NOTIFY),
        (register, LAUNCHER_REGISTER),
        (replied_bit, LAUNCHER_SHELL_REPLIED),
        (volume_launcher, LAUNCHER_VOLUME),
    ];
    launcher_grants[..fixed.len()].copy_from_slice(&fixed);
    for app in 0..APP_SLOTS {
        let at = fixed.len() + app * 7;
        launcher_grants[at] = (app_binder[app], LAUNCHER_APP_BINDER + app);
        launcher_grants[at + 1] = (ended_bits[app], LAUNCHER_SHELL_ENDED + app);
        launcher_grants[at + 2] = (failed_bits[app], LAUNCHER_SHELL_FAILED + app);
        launcher_grants[at + 3] = (ks_channels[app], LAUNCHER_KS_CHANNEL + app);
        launcher_grants[at + 4] = (st_channels[app], LAUNCHER_ST_CHANNEL + app);
        launcher_grants[at + 5] = (in_channels[app], LAUNCHER_IN_CHANNEL + app);
        launcher_grants[at + 6] = (id_channels[app], LAUNCHER_ID_CHANNEL + app);
    }
    let launcher_grants = &launcher_grants[..fixed.len() + 7 * APP_SLOTS];
    // A driver with no device gets its endpoint and its failure report, and nothing to drive.
    let rng_grants = [(rng_endpoint, D_ENDPOINT), (system_failed_bit, D_FAILURE), (rng_irq, D_IRQ), (rng_notify, D_NOTIFY), (rng_dma, D_DMA)];
    let net_driver_grants =
        [(net_driver_endpoint, D_ENDPOINT), (system_failed_bit, D_FAILURE), (net_irq, D_IRQ), (net_rx_bit, D_NOTIFY), (net_dma, D_DMA)];
    fn driver_grants(grants: &[(CPtr, CPtr); 5], present: bool) -> &[(CPtr, CPtr)] {
        if present {
            grants
        } else {
            &grants[..2]
        }
    }
    let disk_grants = [
        (driver_endpoint, DRIVER_ENDPOINT),
        (driver_irq, DRIVER_IRQ),
        (driver_notify, DRIVER_NOTIFY),
        (driver_dma, DRIVER_DMA),
        (system_failed_bit, DRIVER_FAILURE),
    ];
    let disk_grants_polled =
        [(driver_endpoint, DRIVER_ENDPOINT), (driver_notify, DRIVER_NOTIFY), (driver_dma, DRIVER_DMA), (system_failed_bit, DRIVER_FAILURE)];
    let specs = [
        ProgramSpec {
            elf_bytes: SHELL_ELF,
            arg0: shell_arg0(),
            grants: &shell_grants,
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: KEYSTORE_SERVICE_ELF,
            arg0: ARG0_KEYSTORE_SYSTEM | launch::BINDER_LAUNCHED | launch::AUDITED,
            grants: &[(endpoint, KEYSTORE_ENDPOINT_CPTR), (keystore_writer, launch::SERVICE_AUDIT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: STORE_SERVICE_ELF,
            arg0: ARG0_STORE | launch::BINDER_LAUNCHED | launch::AUDITED | MANY_CLIENTS | STORE_ON_DISK,
            grants: &[
                (endpoint, STORE_KS_ENDPOINT_CPTR),
                (store_endpoint, STORE_OWN_ENDPOINT_CPTR),
                (store_writer, launch::SERVICE_AUDIT_CPTR),
                (volume_store, STORE_VOLUME),
            ],
            self_cnode_dest: Some(STORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: LAUNCH_BINDER_ELF,
            arg0: launch::WITH_CONSENT | WITH_LAUNCHER | launch::BINDER_CONSENT_LIMIT,
            grants: &[
                (binder_endpoint, launch::BINDER_ENDPOINT_CPTR),
                (policy_client, launch::BINDER_POLICY_STORE_CPTR),
                (granter, launch::BINDER_KEYSTORE_GRANTER_CPTR),
                (store_granter, launch::BINDER_STORE_GRANTER_CPTR),
                (ask_bit, launch::BINDER_SHELL_ASK_CPTR),
                (answer, launch::BINDER_ANSWER_CPTR),
                (binder_deadline, launch::BINDER_DEADLINE_CPTR),
                (timed_out_bit, launch::BINDER_ANSWER_TIMED_OUT_CPTR),
                (ask_done_bit, launch::BINDER_SHELL_DONE_CPTR),
                (ask_cancelled_bit, launch::BINDER_SHELL_CANCELLED_CPTR),
                (volume_binder, BINDER_VOLUME),
                (inference_granter, BINDER_INFERENCE_GRANTER),
                (wallet_granter, BINDER_WALLET_GRANTER),
            ],
            self_cnode_dest: Some(BINDER_SELF_CNODE_CPTR),
            heap_megapages: launch::BINDER_HEAP_MEGAPAGES,
            arena: Some(ArenaGrant { megapages: SET_FRAMES, self_vspace_dest: BINDER_SELF_VSPACE, frame_dest_base: BINDER_SET_FRAMES }),
        },
        ProgramSpec {
            elf_bytes: LAUNCHER_ELF,
            arg0: LAUNCHER_HOLD,
            grants: launcher_grants,
            self_cnode_dest: Some(LAUNCHER_SELF_CNODE),
            heap_megapages: LAUNCHER_HEAP_MEGAPAGES,
            arena: Some(ArenaGrant { megapages: SET_FRAMES, self_vspace_dest: LAUNCHER_SELF_VSPACE, frame_dest_base: LAUNCHER_SET_FRAMES }),
        },
        ProgramSpec {
            elf_bytes: POLICY_STORE_ELF,
            arg0: launch::POLICY_STORE_QUOTA | POLICY_STORE_ON_DISK | POLICY_STORE_WITH_ARCHIVER,
            grants: &[
                (policy_endpoint, launch::POLICY_STORE_ENDPOINT_CPTR),
                (system_failed_bit, POLICY_STORE_FAILURE_CPTR),
                (volume_policy, POLICY_STORE_VOLUME),
                (archiver_wake, POLICY_STORE_ARCHIVER_WAKE),
            ],
            self_cnode_dest: None,
            heap_megapages: POLICY_STORE_MIRROR_MEGAPAGES,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: disk.elf(),
            arg0: disk.arg0(),
            grants: if disk.line().is_some() { &disk_grants } else { &disk_grants_polled },
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: Some(ArenaGrant { megapages: 0, self_vspace_dest: DRIVER_SELF_VSPACE, frame_dest_base: 0 }),
        },
        ProgramSpec {
            elf_bytes: VOLUME_ELF,
            arg0: 0,
            grants: &[(volume_endpoint, VOLUME_ENDPOINT), (driver_for_volume, VOLUME_DRIVER), (system_failed_bit, VOLUME_FAILURE)],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: INFERENCE_SERVICE_ELF,
            arg0: INFERENCE_ARG0,
            grants: &[
                (inference_endpoint, INFERENCE_ENDPOINT),
                (inference_writer, INFERENCE_AUDIT),
                (volume_models, INFERENCE_VOLUME),
                (system_failed_bit, INFERENCE_FAILURE),
            ],
            self_cnode_dest: Some(INFERENCE_SELF_CNODE),
            heap_megapages: INFERENCE_HEAP_MEGAPAGES,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: RNG_DRIVER_ELF,
            arg0: if rng_device.is_some() { 0 } else { DEVICE_ABSENT },
            grants: driver_grants(&rng_grants, rng_device.is_some()),
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: Some(ArenaGrant { megapages: 0, self_vspace_dest: D_SELF_VSPACE, frame_dest_base: 0 }),
        },
        ProgramSpec {
            elf_bytes: NET_DRIVER_ELF,
            arg0: if net_device.is_some() { 0 } else { DEVICE_ABSENT },
            grants: driver_grants(&net_driver_grants, net_device.is_some()),
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: Some(ArenaGrant { megapages: 0, self_vspace_dest: D_SELF_VSPACE, frame_dest_base: 0 }),
        },
        ProgramSpec {
            elf_bytes: NET_ELF,
            arg0: 0,
            grants: &[
                (net_endpoint, N_ENDPOINT),
                (net_driver_for_net, N_DRIVER),
                (net_notification, N_NOTIFY),
                (net_deadline, N_DEADLINE),
                (net_timer_bit, N_TIMER_BIT),
                (system_failed_bit, N_FAILURE),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: WALLET_ELF,
            arg0: 0,
            grants: &[
                (wallet_endpoint, W_ENDPOINT),
                (wallet_writer, W_AUDIT),
                (volume_wallet, W_VOLUME),
                (rng_for_wallet, W_RNG),
                (net_for_wallet, W_NET),
                (keystore_for_wallet, W_KEYSTORE),
                (system_failed_bit, W_FAILURE),
            ],
            self_cnode_dest: Some(W_SELF_CNODE),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: ARCHIVER_ELF,
            arg0: 0,
            grants: &[
                (archiver_endpoint, A_ENDPOINT),
                (policy_archiver, A_POLICY),
                (keystore_for_archiver, A_KEYSTORE),
                (volume_archive, A_VOLUME),
                (system_failed_bit, A_FAILURE),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
    ];
    let [shell, keystore, store, binder, launcher, policy_store, driver, volume, inference, rng_driver, net_driver, net, wallet, archiver] =
        launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    launch::map_small_device_frame(state, root, uart_page(), shell.vspace_cptr, SHELL_UART_VADDR, &mut next_slot);
    // The runtime's ELF, the launcher's alone. The packages are on the disk.
    launch::map_set(state, root, untyped_cptr, &[CONFINED_RUNTIME_ELF], &[launcher.vspace_cptr], LAUNCHER_RUNTIME_VADDR, &mut next_slot);
    // Each app slot's channels, in their services for good.
    let rw = launch::PERM_R | launch::PERM_W | launch::PERM_U;
    for app in 0..APP_SLOTS {
        let at = app * CHANNEL_STRIDE;
        launch::map(state, root, ks_channels[app], keystore.vspace_cptr, KEYSTORE_CHANNEL_VADDR + at, rw);
        launch::map(state, root, st_channels[app], store.vspace_cptr, STORE_CLIENT_FRAME_VADDR + at, rw);
        launch::map(state, root, in_channels[app], inference.vspace_cptr, INFERENCE_CLIENT_VADDR + at, rw);
        launch::map(state, root, id_channels[app], wallet.vspace_cptr, W_CLIENT_VADDR + at, rw);
    }
    // RFC-0034: the shell's channel to the store, for `write`.
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        store.vspace_cptr,
        STORE_CONSOLE_FRAME_VADDR,
        shell.vspace_cptr,
        SHELL_STORE_CONSOLE_VADDR,
        &mut next_slot,
    );
    // The store's own channel to the keystore, after the apps'.
    let store_channel_on_keystore = KEYSTORE_CHANNEL_VADDR + APP_SLOTS * CHANNEL_STRIDE;
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        keystore.vspace_cptr,
        store_channel_on_keystore,
        store.vspace_cptr,
        STORE_KS_FRAME_VADDR,
        &mut next_slot,
    );
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        binder.vspace_cptr,
        launch::CONSENT_VADDR,
        shell.vspace_cptr,
        launch::CONSENT_VADDR,
        &mut next_slot,
    );
    launch::map_shared_frame(
        state,
        root,
        untyped_cptr,
        launcher.vspace_cptr,
        LAUNCHER_COMMAND_VADDR,
        shell.vspace_cptr,
        SHELL_LAUNCHER_VADDR,
        &mut next_slot,
    );
    // RFC-0031: the disk's register page and every channel to and from the volume.
    for page in 0..disk.register_pages() {
        let (paddr, vaddr) = (disk.paddr() + page * 0x1000, DRIVER_REGS_VADDR + page * 0x1000);
        launch::map_small_device_frame(state, root, paddr, driver.vspace_cptr, vaddr, &mut next_slot);
    }
    let mut share = |state: &mut _, a, a_vaddr, b, b_vaddr| {
        launch::map_shared_frame(state, root, untyped_cptr, a, a_vaddr, b, b_vaddr, &mut next_slot)
    };
    share(state, driver.vspace_cptr, DRIVER_CHANNEL_VADDR, volume.vspace_cptr, VOLUME_DRIVER_VADDR);
    for (client, vaddr, badge) in [
        (launcher.vspace_cptr, CLIENT_VOLUME_VADDR, VOLUME_BADGE_LAUNCHER),
        (store.vspace_cptr, STORE_VOLUME_VADDR, VOLUME_BADGE_STORE),
        (binder.vspace_cptr, CLIENT_VOLUME_VADDR, VOLUME_BADGE_BINDER),
        (policy_store.vspace_cptr, POLICY_STORE_VOLUME_VADDR, VOLUME_BADGE_POLICY),
        (inference.vspace_cptr, INFERENCE_VOLUME_VADDR, VOLUME_BADGE_MODELS),
        (wallet.vspace_cptr, W_VOLUME_VADDR, VOLUME_BADGE_WALLET),
        (archiver.vspace_cptr, A_VOLUME_VADDR, VOLUME_BADGE_ARCHIVE),
    ] {
        let at = VOLUME_CLIENT_VADDR + (badge as usize - 1) * CHANNEL_STRIDE;
        share(state, volume.vspace_cptr, at, client, vaddr);
    }
    // RFC-0035: the drivers' register pages, and the channels between the network card's driver and `net`, `net` and the
    // wallet, and the keystore and the wallet.
    for (found, program) in [(rng_device, &rng_driver), (net_device, &net_driver)] {
        if let Some((paddr, _)) = found {
            launch::map_small_device_frame(state, root, paddr, program.vspace_cptr, DRIVER_REGS_VADDR, &mut next_slot);
        }
    }
    let mut share = |state: &mut _, a, a_vaddr, b, b_vaddr| {
        launch::map_shared_frame(state, root, untyped_cptr, a, a_vaddr, b, b_vaddr, &mut next_slot)
    };
    share(state, net_driver.vspace_cptr, DRIVER_CHANNEL_VADDR, net.vspace_cptr, N_DRIVER_VADDR);
    share(state, net.vspace_cptr, N_CLIENT_VADDR, wallet.vspace_cptr, W_NET_VADDR);
    let keystore_wallet = KEYSTORE_CHANNEL_VADDR + KEYSTORE_WALLET_CHANNEL * CHANNEL_STRIDE;
    share(state, keystore.vspace_cptr, keystore_wallet, wallet.vspace_cptr, W_KEYSTORE_VADDR);
    // RFC-0038: the page the policy store copies a sector's words into for the archiver, and the archiver's keystore channel.
    share(state, policy_store.vspace_cptr, POLICY_STORE_ARCHIVER_PAGE_VADDR, archiver.vspace_cptr, A_POLICY_PAGE_VADDR);
    let keystore_archiver = KEYSTORE_CHANNEL_VADDR + KEYSTORE_ARCHIVER_CHANNEL * CHANNEL_STRIDE;
    share(state, keystore.vspace_cptr, keystore_archiver, archiver.vspace_cptr, A_KEYSTORE_VADDR);
    for tcb in [
        keystore.tcb,
        store.tcb,
        binder.tcb,
        launcher.tcb,
        policy_store.tcb,
        driver.tcb,
        volume.tcb,
        inference.tcb,
        rng_driver.tcb,
        net_driver.tcb,
        net.tcb,
        wallet.tcb,
        archiver.tcb,
    ] {
        state.make_ready(tcb);
    }
    crate::println!(
        "system: {} root slots, {} Frames, {} CNodes, {} VSpaces, {} TCBs, {} page tables before any app",
        next_slot,
        state.frames.len(),
        state.cnodes.len(),
        state.vspaces.len(),
        state.tcbs.len(),
        state.kernel_page_tables.in_use()
    );
    crate::println!("system: starting the shell; from here on, only the shell writes to this console");
    // SAFETY: called once, after every program's capabilities, address space and context were populated above.
    unsafe { lantern_kernel::enter_first_thread(shell.tcb) }
}
