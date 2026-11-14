//! Boots [RFC-0026](../../../lantern-rfcs/rfcs/0026-trusted-path-and-consent.md)'s **interactive system image**: the first
//! boot image that is a system rather than a demo. A person decides each grant at a console only the shell can reach.
//!
//! Five confined programs:
//!
//! - **`lantern-shell/shell/`** holds the UART's 4 KiB page and its `IrqHandler`, so it is the only program that can
//!   read or write the console. It also holds the binder's control capability, the audit log's read-only one, and one
//!   capability per answer to the binder's answer notification. It waits on one notification, whose badge bits are its
//!   inputs: `CONSOLE` (bound by the shell itself), `ASK` (the binder), `APP_DONE`/`APP_FAILED` (the runtime), and
//!   `SYSTEM_FAILED` (the policy store's panic report).
//! - **`lantern-shell/launch-binder/`**, launched `WITH_CONSENT`: its policy is a ceiling, and inside it the person is asked,
//!   through the consent `Frame` it shares with the shell.
//! - **`lantern-shell/policy-store/`**, on `virt.flash1`, which keeps revocations, remembered decisions and the audit log.
//!   **This image needs that flash attached:** `-drive if=pflash,format=raw,unit=1,file=<32 MiB image of 0xFF bytes>`.
//! - **`keystore-service`**, audited, granting only over the binder's `GRANT`.
//! - **`confined-runtime`**, hosting the signed `probe.lpkg` in system mode: its `probe` runs once, and it reports to the
//!   shell instead of to `grant-control`, which isn't here. Then it parks.
//!
//! **The boot code and the kernel stay off the console once the shell runs** (ADR-0031): this image's trap handler
//! narrates nothing, and only a panic prints.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ArenaGrant, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const KEYSTORE_SERVICE_ELF: &[u8] = include_bytes!("../../assets/keystore-service.elf");
const CONFINED_RUNTIME_ELF: &[u8] = include_bytes!("../../assets/confined-runtime.elf");
const LAUNCH_BINDER_ELF: &[u8] = include_bytes!("../../assets/launch-binder.elf");
const POLICY_STORE_ELF: &[u8] = include_bytes!("../../assets/policy-store.elf");
const SHELL_ELF: &[u8] = include_bytes!("../../assets/shell.elf");
/// The one app this image runs. A user-space launcher, step 3 of RFC-0026's roadmap track, would let a person choose.
const PROBE_LPKG: &[u8] = include_bytes!("../../assets/probe.lpkg");

/// As `runtime_demo/loader.rs`'s constants of the same names.
const ENDPOINT_CPTR: CPtr = 1;
const KEYSTORE_SELF_CNODE_CPTR: CPtr = 0;
const RUNTIME_SUCCESS_CPTR: CPtr = 3;
const RUNTIME_FAILURE_CPTR: CPtr = 4;
const RUNTIME_SELF_VSPACE_CPTR: CPtr = 6;
const RUNTIME_ARENA_FRAME_CPTR_BASE: CPtr = 7;
const RUNTIME_ARENA_MEGAPAGES: usize = 3;
const RUNTIME_HEAP_MEGAPAGES: usize = 1;
/// `confined-runtime`'s `PARK_CPTR`: a notification nothing signals, so the runtime waits instead of spinning.
const RUNTIME_PARK_CPTR: CPtr = 12;
const FRAME_VADDR: usize = 0x9000_0000;
const ARG0_KEYSTORE_SIGNING: usize = 1;
/// `policy-store`'s panic report.
const POLICY_STORE_FAILURE_CPTR: CPtr = 4;

/// `shell/src/main.rs`'s slots and addresses.
const SHELL_IRQ_CPTR: CPtr = 1;
const SHELL_NOTIFY_CPTR: CPtr = 2;
const SHELL_CONSOLE_BIT_CPTR: CPtr = 3;
const SHELL_CONTROL_CPTR: CPtr = 4;
const SHELL_READER_CPTR: CPtr = 5;
const SHELL_ANSWER_CPTR_BASE: CPtr = 6;
const SHELL_UART_VADDR: usize = 0x9500_0000;

/// `lantern_abi::consent::bit`, and `Answer::badge`'s values, in the order the shell holds them.
const BIT_CONSOLE: u64 = 1 << 0;
const BIT_ASK: u64 = 1 << 1;
const BIT_APP_DONE: u64 = 1 << 2;
const BIT_APP_FAILED: u64 = 1 << 3;
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

    // The keystore, its granter capability (the binder's alone), and the binder's endpoint and its two badges.
    let endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let granter = mint(state, &mut next_slot, endpoint, Rights::WRITE, launch::GRANTER_BADGE);
    let binder_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let binder_client = mint(state, &mut next_slot, binder_endpoint, Rights::WRITE, 0);
    let binder_control = mint(state, &mut next_slot, binder_endpoint, Rights::WRITE, launch::CONTROL_BADGE);
    // The policy store, and its binder, reader and keystore-writer badges.
    let policy_endpoint = retype(state, &mut next_slot, ObjectType::Endpoint);
    let policy_client = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, 0);
    let policy_reader = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, launch::READER_BADGE);
    let keystore_writer = mint(state, &mut next_slot, policy_endpoint, Rights::WRITE, launch::KEYSTORE_WRITER_BADGE);
    // The shell's notification, and one write-only badge for each of its inputs.
    let shell_notify = retype(state, &mut next_slot, ObjectType::Notification);
    let console_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_CONSOLE);
    let ask_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_ASK);
    let app_done_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_APP_DONE);
    let app_failed_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_APP_FAILED);
    let system_failed_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_SYSTEM_FAILED);
    let ask_done_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_ASK_DONE);
    let ask_cancelled_bit = mint(state, &mut next_slot, shell_notify, Rights::WRITE, BIT_ASK_CANCELLED);
    // The binder's answer notification, and one write-only badge per answer, all the shell's.
    let answer = retype(state, &mut next_slot, ObjectType::Notification);
    let answers = ANSWER_BADGES.map(|badge| mint(state, &mut next_slot, answer, Rights::WRITE, badge));
    // RFC-0028: the binder's deadline, bound by the binder to its own answer notification under `TIMED_OUT`.
    let timed_out_bit = mint(state, &mut next_slot, answer, Rights::WRITE, BIT_TIMED_OUT);
    let binder_deadline = slot(&mut next_slot);
    launch::deadline(state, root, binder_deadline);
    let park = retype(state, &mut next_slot, ObjectType::Notification);
    let irq = slot(&mut next_slot);
    launch::irq_handler(state, root, UART_LINE, irq);

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
    ];
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
            arg0: ARG0_KEYSTORE_SIGNING | launch::BINDER_LAUNCHED | launch::AUDITED,
            grants: &[(endpoint, ENDPOINT_CPTR), (keystore_writer, launch::SERVICE_AUDIT_CPTR)],
            self_cnode_dest: Some(KEYSTORE_SELF_CNODE_CPTR),
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: LAUNCH_BINDER_ELF,
            arg0: PROBE_LPKG.len() | launch::WITH_CONSENT | launch::BINDER_CONSENT_LIMIT,
            grants: &[
                (binder_endpoint, launch::BINDER_ENDPOINT_CPTR),
                (policy_client, launch::BINDER_POLICY_STORE_CPTR),
                (granter, launch::BINDER_KEYSTORE_GRANTER_CPTR),
                (ask_bit, launch::BINDER_SHELL_ASK_CPTR),
                (answer, launch::BINDER_ANSWER_CPTR),
                (binder_deadline, launch::BINDER_DEADLINE_CPTR),
                (timed_out_bit, launch::BINDER_ANSWER_TIMED_OUT_CPTR),
                (ask_done_bit, launch::BINDER_SHELL_DONE_CPTR),
                (ask_cancelled_bit, launch::BINDER_SHELL_CANCELLED_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: launch::BINDER_HEAP_MEGAPAGES,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: CONFINED_RUNTIME_ELF,
            arg0: PROBE_LPKG.len() | launch::WITH_CONSENT,
            grants: &[
                (binder_client, ENDPOINT_CPTR),
                (app_done_bit, RUNTIME_SUCCESS_CPTR),
                (app_failed_bit, RUNTIME_FAILURE_CPTR),
                (park, RUNTIME_PARK_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: RUNTIME_HEAP_MEGAPAGES,
            arena: Some(ArenaGrant {
                megapages: RUNTIME_ARENA_MEGAPAGES,
                self_vspace_dest: RUNTIME_SELF_VSPACE_CPTR,
                frame_dest_base: RUNTIME_ARENA_FRAME_CPTR_BASE,
            }),
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
    let [shell, service, binder, runtime, policy_store] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    launch::map_device_frame(state, root, launch::POLICY_FLASH_PADDR, policy_store.vspace_cptr, launch::POLICY_FLASH_VADDR, &mut next_slot);
    launch::map_small_device_frame(state, root, UART_PADDR, shell.vspace_cptr, SHELL_UART_VADDR, &mut next_slot);
    launch::map_package(state, root, untyped_cptr, PROBE_LPKG, &[binder.vspace_cptr, runtime.vspace_cptr], &mut next_slot);
    launch::map_shared_frame(state, root, untyped_cptr, service.vspace_cptr, FRAME_VADDR, runtime.vspace_cptr, FRAME_VADDR, &mut next_slot);
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
    for tcb in [service.tcb, binder.tcb, runtime.tcb, policy_store.tcb] {
        state.make_ready(tcb);
    }
    crate::println!("system: starting the shell; from here on, only the shell writes to this console");
    // SAFETY: called once, after every program's capabilities, address space and context were populated above.
    unsafe { lantern_kernel::enter_first_thread(shell.tcb) }
}
