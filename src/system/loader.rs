//! Boots [RFC-0026](../../../lantern-rfcs/rfcs/0026-trusted-path-and-consent.md)'s **interactive system image**: the first
//! boot image that is a system rather than a demo. A person decides each grant at a console only the shell can reach, and
//! since [RFC-0029](../../../lantern-rfcs/rfcs/0029-a-confined-launcher.md), runs the apps they choose there.
//!
//! Six confined programs, and no app until a person asks:
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
//! - **`lantern-shell/policy-store/`**, on `virt.flash1`, which keeps remembered decisions and the audit log. **This image
//!   needs that flash attached:** `-drive if=pflash,format=raw,unit=1,file=<32 MiB image of 0xFF bytes>`, and at least
//!   `-m 256M` for the apps' memory.
//! - **`keystore-service`**, in its system profile: the apps' signing key, granted only over the binder's `GRANT`, and the
//!   store's sealing key, granted once to its first caller, the store. One channel per app slot, and the store's.
//! - **`store-service`**, sealing each block through the keystore, with one channel per app slot.
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
const POLICY_STORE_ELF: &[u8] = include_bytes!("../../assets/policy-store.elf");
const SHELL_ELF: &[u8] = include_bytes!("../../assets/shell.elf");
/// The package set: what `apps` lists.
const PACKAGES: [&[u8]; 2] = [include_bytes!("../../assets/probe.lpkg"), include_bytes!("../../assets/fs-probe.lpkg")];

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
/// `policy-store`'s panic report.
const POLICY_STORE_FAILURE_CPTR: CPtr = 4;
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
const SET_VADDR: usize = 0x8c00_0000;

/// `lantern_abi::consent::bit`, and `Answer::badge`'s values, in the order the shell holds them.
const BIT_CONSOLE: u64 = 1 << 0;
const BIT_ASK: u64 = 1 << 1;
const BIT_SYSTEM_FAILED: u64 = 1 << 4;
const BIT_ASK_DONE: u64 = 1 << 5;
const BIT_ASK_CANCELLED: u64 = 1 << 6;
/// `lantern_abi::consent::TIMED_OUT`, on the binder's answer notification.
const BIT_TIMED_OUT: u64 = 1 << 4;
const ANSWER_BADGES: [u64; 4] = [1 << 0, 1 << 1, 1 << 2, 1 << 3];

const UART_PADDR: usize = 0x1000_0000;
const UART_LINE: u16 = 10;

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
    let mem_end = mem_end.max(pmm::GENERAL_MEMORY_BASE + lantern_hal::RISCV64_MEGAPAGE_SIZE)
        & !(lantern_hal::RISCV64_MEGAPAGE_SIZE - 1);
    let untyped = Untyped::with_memory(1000, pmm::GENERAL_MEMORY_BASE, mem_end - pmm::GENERAL_MEMORY_BASE);
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
    launch::irq_handler(state, root, UART_LINE, irq);
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
    ];
    let mut launcher_grants = [(0, 0); 6 + 5 * APP_SLOTS];
    let fixed = [
        (app_memory, LAUNCHER_MEMORY),
        (launcher_notify, LAUNCHER_NOTIFY),
        (register, LAUNCHER_REGISTER),
        (replied_bit, LAUNCHER_SHELL_REPLIED),
    ];
    launcher_grants[..fixed.len()].copy_from_slice(&fixed);
    for app in 0..APP_SLOTS {
        let at = fixed.len() + app * 5;
        launcher_grants[at] = (app_binder[app], LAUNCHER_APP_BINDER + app);
        launcher_grants[at + 1] = (ended_bits[app], LAUNCHER_SHELL_ENDED + app);
        launcher_grants[at + 2] = (failed_bits[app], LAUNCHER_SHELL_FAILED + app);
        launcher_grants[at + 3] = (ks_channels[app], LAUNCHER_KS_CHANNEL + app);
        launcher_grants[at + 4] = (st_channels[app], LAUNCHER_ST_CHANNEL + app);
    }
    let launcher_grants = &launcher_grants[..fixed.len() + 5 * APP_SLOTS];
    let specs = [
        ProgramSpec {
            elf_bytes: SHELL_ELF,
            arg0: 0,
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
            arg0: ARG0_STORE | launch::BINDER_LAUNCHED | launch::AUDITED | MANY_CLIENTS,
            grants: &[
                (endpoint, STORE_KS_ENDPOINT_CPTR),
                (store_endpoint, STORE_OWN_ENDPOINT_CPTR),
                (store_writer, launch::SERVICE_AUDIT_CPTR),
            ],
            self_cnode_dest: Some(STORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: LAUNCH_BINDER_ELF,
            arg0: PACKAGES.len() | launch::WITH_CONSENT | WITH_LAUNCHER | launch::BINDER_CONSENT_LIMIT,
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
            ],
            self_cnode_dest: Some(BINDER_SELF_CNODE_CPTR),
            heap_megapages: launch::BINDER_HEAP_MEGAPAGES,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: LAUNCHER_ELF,
            arg0: PACKAGES.len() | LAUNCHER_HOLD,
            grants: launcher_grants,
            self_cnode_dest: Some(LAUNCHER_SELF_CNODE),
            heap_megapages: LAUNCHER_HEAP_MEGAPAGES,
            arena: Some(ArenaGrant { megapages: 0, self_vspace_dest: LAUNCHER_SELF_VSPACE, frame_dest_base: 0 }),
        },
        ProgramSpec {
            elf_bytes: POLICY_STORE_ELF,
            arg0: launch::POLICY_STORE_QUOTA,
            grants: &[(policy_endpoint, launch::POLICY_STORE_ENDPOINT_CPTR), (system_failed_bit, POLICY_STORE_FAILURE_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
    ];
    let [shell, keystore, store, binder, launcher, policy_store] =
        launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    launch::map_device_frame(state, root, launch::POLICY_FLASH_PADDR, policy_store.vspace_cptr, launch::POLICY_FLASH_VADDR, &mut next_slot);
    launch::map_small_device_frame(state, root, UART_PADDR, shell.vspace_cptr, SHELL_UART_VADDR, &mut next_slot);
    // The package set, the binder's and the launcher's alone; the runtime's ELF, the launcher's alone.
    launch::map_set(state, root, untyped_cptr, &PACKAGES, &[binder.vspace_cptr, launcher.vspace_cptr], SET_VADDR, &mut next_slot);
    launch::map_set(state, root, untyped_cptr, &[CONFINED_RUNTIME_ELF], &[launcher.vspace_cptr], LAUNCHER_RUNTIME_VADDR, &mut next_slot);
    // Each app slot's channels, in their services for good.
    let rw = launch::PERM_R | launch::PERM_W | launch::PERM_U;
    for app in 0..APP_SLOTS {
        let at = app * CHANNEL_STRIDE;
        launch::map(state, root, ks_channels[app], keystore.vspace_cptr, KEYSTORE_CHANNEL_VADDR + at, rw);
        launch::map(state, root, st_channels[app], store.vspace_cptr, STORE_CLIENT_FRAME_VADDR + at, rw);
    }
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
    for tcb in [keystore.tcb, store.tcb, binder.tcb, launcher.tcb, policy_store.tcb] {
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
