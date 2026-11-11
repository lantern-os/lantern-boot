//! Boots RFC-0027's interrupt demo: a **ninth, isolated boot image**, with two confined programs.
//!
//! - `../../uart-driver/` holds the UART's 4 KiB device Frame, an `IrqHandler` for line 10 (the UART on QEMU
//!   `virt`), a badged notification to bind it to, and `DONE`/`FAILURE` notifications. It echoes what's typed
//!   into QEMU's serial input and reports at the first newline.
//! - `../../spinner/` runs **first**, and never makes a system call. So even the driver's first instruction depends
//!   on the timer preempting it. With the `irq-idle` feature, it parks instead, every thread ends up waiting, and the
//!   kernel must idle until a keystroke.
//!
//! `scripts/irq-demo.sh` types into the serial line and checks the driver's report, and in the idle variant QEMU's
//! CPU use while nothing is typed.

use lantern_kernel::cap::{Capability, CNode, CNodeId, CPtr, ObjectType, Rights, TcbId, UntypedId};
use lantern_kernel::object::{Tcb, Untyped};

use crate::launch::{self, ProgramSpec, SELF_CNODE_CPTR};
use crate::pmm;

const UART_DRIVER_ELF: &[u8] = include_bytes!("../../assets/uart-driver.elf");
const SPINNER_ELF: &[u8] = include_bytes!("../../assets/spinner.elf");

/// The UART: its physical page, its PLIC line on QEMU `virt`, and where the driver maps it. Must equal
/// `uart-driver`'s `UART_VADDR`.
const UART_PADDR: usize = 0x1000_0000;
const UART_LINE: u16 = 10;
const UART_VADDR: usize = 0x9500_0000;

/// The driver's slots: must match `uart-driver/src/main.rs`.
const DRIVER_IRQ_CPTR: CPtr = 1;
const DRIVER_NOTIFICATION_CPTR: CPtr = 2;
pub const DRIVER_DONE_CPTR: CPtr = 3;
pub const DRIVER_FAILURE_CPTR: CPtr = 4;
/// The spinner's, for its parked variant.
const SPINNER_PARK_CPTR: CPtr = 1;

/// Delivery ORs this into the driver's notification. Nonzero, which binding requires.
const IRQ_BADGE: u64 = 1;

/// `spinner`'s `arg0`: spin, or park.
const SPINNER_ARG0: usize = if cfg!(feature = "irq-idle") { 1 } else { 0 };

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

    let mut slot = || {
        let s = next_slot;
        next_slot += 1;
        s
    };
    let notification_root = slot();
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, notification_root);
    let badged_notification_root = slot();
    launch::mint(state, root, notification_root, badged_notification_root, Rights::ALL, IRQ_BADGE);
    let done_root = slot();
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, done_root);
    let failure_root = slot();
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, failure_root);
    let park_root = slot();
    launch::retype(state, root, untyped_cptr, ObjectType::Notification, park_root);
    let irq_root = slot();
    launch::irq_handler(state, root, UART_LINE, irq_root);

    let specs = [
        ProgramSpec {
            elf_bytes: SPINNER_ELF,
            arg0: SPINNER_ARG0,
            grants: &[(park_root, SPINNER_PARK_CPTR)],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
        ProgramSpec {
            elf_bytes: UART_DRIVER_ELF,
            arg0: 0,
            grants: &[
                (irq_root, DRIVER_IRQ_CPTR),
                (badged_notification_root, DRIVER_NOTIFICATION_CPTR),
                (done_root, DRIVER_DONE_CPTR),
                (failure_root, DRIVER_FAILURE_CPTR),
            ],
            self_cnode_dest: None,
            heap_megapages: 0,
            arena: None,
        },
    ];
    let [spinner, driver] = launch::load_all(state, root, untyped_cptr, &specs, &mut next_slot);
    launch::map_small_device_frame(state, root, UART_PADDR, driver.vspace_cptr, UART_VADDR, &mut next_slot);

    crate::println!(
        "irq-demo: entering the spinner first ({}); the driver runs only if the kernel preempts it",
        if SPINNER_ARG0 == 0 { "it never yields" } else { "it parks, so the kernel must idle" }
    );
    // SAFETY: called once, after every program's capabilities, address space and context were populated above.
    unsafe { lantern_kernel::enter_first_thread(spinner.tcb) }
}
