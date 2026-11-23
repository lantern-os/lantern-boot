//! `lantern-nvme-driver` — [RFC-0039](../../lantern-rfcs/rfcs/0039-bring-up-on-the-k3-pico-itx.md)'s NVMe driver.
//!
//! It holds one NVMe controller's first two register pages (its registers, and the doorbells of the admin queue and one
//! I/O queue), its `IrqHandler` if the PCIe host routes it an INTx line, a DMA `Untyped` for its queues and data buffer,
//! and its own VSpace to map them. It serves raw sectors over an RFC-0019 channel to one client, under one badge, the
//! volume's, exactly as the virtio-blk driver does. **It parses nothing from the disk.**
//!
//! **It is trusted with all memory.** Until IOMMU confinement (RFC-0039's stream D), the controller reaches whatever
//! physical address the driver writes into a command. It writes only the addresses of its own DMA Frames, which only a
//! DMA `Untyped` can reveal, but nothing below it enforces that. RFC-0023's checklist carries the row.
//!
//! NVMe 1.4: the admin queue, then one I/O submission and completion queue of 16 entries, one command at a time,
//! namespace 1 only, 512-byte logical blocks only (as QEMU's and most drives' default), each transfer at most one 4 KiB
//! page, so one PRP entry. A `WRITE` is followed by a `FLUSH` when the controller has a volatile write cache, and is
//! answered `OK` only once both completed. Without an interrupt line it polls, yielding between looks.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{fence, Ordering};

use lantern_abi::block::{self, badge, MAX_BYTES, SECTOR};
use lantern_abi::frame::{status, Channel, RefuseInterlopers};
use lantern_abi::sys::{self, frame, irq, retype};
use lantern_abi::wire::MapPerms;

// Granted by the loader (`src/system/loader.rs`), as the virtio-blk driver's.
const ENDPOINT: usize = 1;
const IRQ: usize = 2;
const NOTIFY: usize = 3;
const DMA_MEMORY: usize = 4;
const SELF_VSPACE: usize = 5;
const FAILURE: usize = 6;
// Its own.
const ADMIN_SQ_FRAME: usize = 10;
const ADMIN_CQ_FRAME: usize = 11;
const IO_SQ_FRAME: usize = 12;
const IO_CQ_FRAME: usize = 13;
const DATA_FRAME: usize = 14;

/// `arg0`'s bit: the loader granted an `IrqHandler` in `IRQ`. Without one, the driver polls.
pub const ARG0_INTERRUPT: usize = 1;

const REGS_VADDR: usize = 0x9500_0000;
const CHANNEL_VADDR: usize = 0x9000_0000;
const ADMIN_SQ_VADDR: usize = 0x9600_0000;
const ADMIN_CQ_VADDR: usize = 0x9600_1000;
const IO_SQ_VADDR: usize = 0x9600_2000;
const IO_CQ_VADDR: usize = 0x9600_3000;
const DATA_VADDR: usize = 0x9600_4000;
/// The register pages the loader maps.
const REGS_BYTES: usize = 0x2000;

/// Controller registers (NVMe 1.4, §3.1).
const CAP: usize = 0x00;
const VS: usize = 0x08;
const INTMC: usize = 0x10;
const CC: usize = 0x14;
const CSTS: usize = 0x1c;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
const DOORBELLS: usize = 0x1000;

const CC_ENABLE: u32 = 1;
/// I/O completion queue entries are 16 bytes (2^4), submission queue entries 64 (2^6).
const CC_IOCQES: u32 = 4 << 20;
const CC_IOSQES: u32 = 6 << 16;
const CSTS_READY: u32 = 1;
const CSTS_FATAL: u32 = 1 << 1;

/// Entries in each queue: a page of submissions is 64 of them, but one command is ever outstanding.
const ENTRIES: u16 = 16;
const SQE: usize = 64;
const CQE: usize = 16;

/// Admin and NVM command opcodes.
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const NVM_FLUSH: u8 = 0x00;
const NVM_WRITE: u8 = 0x01;
const NVM_READ: u8 = 0x02;
const NAMESPACE: u32 = 1;
const IO_QUEUE: u16 = 1;

/// How long to spin, at most, for the controller to change state, in looks: CAP.TO is in 500 ms units, and each look
/// yields the processor. Generous, since only a broken controller runs it out.
const READY_LOOKS: u32 = 2_000_000;

lantern_abi::entry!(run);

fn reg32(offset: usize) -> u32 {
    // SAFETY: the loader mapped the controller's first two register pages read/write at REGS_VADDR for this program's
    // whole life; `offset` is a register inside them.
    unsafe { core::ptr::read_volatile((REGS_VADDR + offset) as *const u32) }
}

fn set32(offset: usize, value: u32) {
    // SAFETY: as `reg32`.
    unsafe { core::ptr::write_volatile((REGS_VADDR + offset) as *mut u32, value) }
}

/// A 64-bit register, read as two 32-bit halves, low first, as the specification allows.
fn reg64(offset: usize) -> u64 {
    reg32(offset) as u64 | (reg32(offset + 4) as u64) << 32
}

fn set64(offset: usize, value: u64) {
    set32(offset, value as u32);
    set32(offset + 4, (value >> 32) as u32);
}

/// Orders every memory and device access before it against every one after: the controller reads the queues by DMA.
fn barrier() {
    fence(Ordering::SeqCst);
    // SAFETY: a fence has no operands and no effect beyond ordering.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack))
    };
}

fn data() -> &'static mut [u8] {
    // SAFETY: the data page is mapped read/write at DATA_VADDR, and only this single thread touches it, between requests.
    unsafe { core::slice::from_raw_parts_mut(DATA_VADDR as *mut u8, MAX_BYTES) }
}

/// One queue pair: its submission queue's page and tail, its completion queue's page, head and phase, its doorbells.
struct Queue {
    sq: usize,
    cq: usize,
    tail: u16,
    head: u16,
    phase: bool,
    sq_doorbell: usize,
    cq_doorbell: usize,
    next_id: u16,
}

impl Queue {
    fn new(id: u16, sq: usize, cq: usize, stride: usize) -> Self {
        let sq_doorbell = DOORBELLS + (2 * id as usize) * stride;
        Self { sq, cq, tail: 0, head: 0, phase: true, sq_doorbell, cq_doorbell: sq_doorbell + stride, next_id: 0 }
    }
}

/// A command's dwords: 0 (opcode and command ID are filled in), 1 (namespace), PRP1, and 10 to 15.
struct Command {
    opcode: u8,
    namespace: u32,
    prp1: u64,
    cdw: [u32; 6],
}

struct Controller {
    admin: Queue,
    io: Queue,
    data_paddr: u64,
    interrupt: bool,
    capacity: u64,
    flush: bool,
}

fn run(arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    let mut controller = init(arg0 & ARG0_INTERRUPT != 0).unwrap_or_else(|step| fail(step));
    // SAFETY: the loader mapped the channel shared with the volume read/write at CHANNEL_VADDR.
    let mut channel = unsafe { Channel::new(ENDPOINT, CHANNEL_VADDR as *mut u8) };
    let mut request = [0u8; block::HEADER + MAX_BYTES];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if received.badge != badge::VOLUME {
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        }
        let Ok((op, len)) = channel.recv_request(received, &mut request, &mut RefuseInterlopers) else { continue };
        let (outcome, reply_len) = serve(&mut controller, op, &request[..len]);
        let _ = channel.reply(outcome, &data()[..reply_len], received.badge, &mut RefuseInterlopers);
    }
}

fn serve(controller: &mut Controller, op: u16, request: &[u8]) -> (u16, usize) {
    if op == block::OP_INFO {
        data()[..8].copy_from_slice(&controller.capacity.to_le_bytes());
        return (status::OK, 8);
    }
    let Some((first, count)) = block::decode_range(request) else { return (status::INVALID, 0) };
    if !block::within(first, count, controller.capacity) {
        return (status::INVALID, 0);
    }
    let bytes = count * SECTOR;
    match op {
        block::OP_READ => match count > 0 && controller.transfer(NVM_READ, first, count) {
            true => (status::OK, bytes),
            false if count == 0 => (status::OK, 0),
            false => (status::FAILED, 0),
        },
        block::OP_WRITE if request.len() == block::HEADER + bytes => {
            if count == 0 {
                return (status::OK, 0);
            }
            data()[..bytes].copy_from_slice(&request[block::HEADER..]);
            let done = controller.transfer(NVM_WRITE, first, count) && (!controller.flush || controller.flush());
            (if done { status::OK } else { status::FAILED }, 0)
        }
        _ => (status::INVALID, 0),
    }
}

/// Waits, at most [`READY_LOOKS`] looks, for `CSTS.RDY` to be `ready`. `false` on a fatal status or running out.
fn await_ready(ready: bool) -> bool {
    for _ in 0..READY_LOOKS {
        let csts = reg32(CSTS);
        if csts & CSTS_FATAL != 0 {
            return false;
        }
        if (csts & CSTS_READY != 0) == ready {
            return true;
        }
        let _ = sys::yield_now();
    }
    false
}

/// Brings the controller up (NVMe 1.4, §7.6.1), or says at which step it failed.
fn init(interrupt: bool) -> Result<Controller, usize> {
    let cap = reg64(CAP);
    // A controller reporting no version, or not the NVM command set, or a smallest page bigger than 4 KiB, isn't one
    // this driver can use.
    if reg32(VS) == 0 || cap & (1 << 37) == 0 || (cap >> 48) & 0xf != 0 || (cap & 0xffff) + 1 < ENTRIES as u64 {
        return Err(1);
    }
    let stride = 4usize << ((cap >> 32) & 0xf);
    if DOORBELLS + 4 * stride > REGS_BYTES {
        return Err(1);
    }
    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    let mut paddr = [0u64; 5];
    for (i, (cap, vaddr)) in [
        (ADMIN_SQ_FRAME, ADMIN_SQ_VADDR),
        (ADMIN_CQ_FRAME, ADMIN_CQ_VADDR),
        (IO_SQ_FRAME, IO_SQ_VADDR),
        (IO_CQ_FRAME, IO_CQ_VADDR),
        (DATA_FRAME, DATA_VADDR),
    ]
    .into_iter()
    .enumerate()
    {
        retype::frame_small(DMA_MEMORY, cap).map_err(|_| 2usize)?;
        frame::map(cap, SELF_VSPACE, vaddr, rw).map_err(|_| 3usize)?;
        paddr[i] = frame::address(cap).map_err(|_| 4usize)? as u64;
    }

    // Reset, then the admin queue, then enable.
    set32(CC, 0);
    if !await_ready(false) {
        return Err(5);
    }
    set32(AQA, ((ENTRIES as u32 - 1) << 16) | (ENTRIES as u32 - 1));
    set64(ASQ, paddr[0]);
    set64(ACQ, paddr[1]);
    set32(CC, CC_IOCQES | CC_IOSQES | CC_ENABLE);
    if !await_ready(true) {
        return Err(6);
    }
    // Every vector unmasked: INTx is vector 0.
    set32(INTMC, 1);

    let mut controller = Controller {
        admin: Queue::new(0, ADMIN_SQ_VADDR, ADMIN_CQ_VADDR, stride),
        io: Queue::new(IO_QUEUE, IO_SQ_VADDR, IO_CQ_VADDR, stride),
        data_paddr: paddr[4],
        interrupt,
        capacity: 0,
        flush: false,
    };
    if interrupt && irq::set_notification(IRQ, NOTIFY).is_err() {
        return Err(7);
    }

    // Identify the controller: byte 525 bit 0 is a volatile write cache, which writes must be flushed through.
    let identify = |c: &mut Controller, cns: u32, namespace: u32| {
        c.admin_command(Command { opcode: ADMIN_IDENTIFY, namespace, prp1: c.data_paddr, cdw: [cns, 0, 0, 0, 0, 0] })
    };
    if !identify(&mut controller, 1, 0) {
        return Err(8);
    }
    controller.flush = data()[525] & 1 != 0;
    // Identify namespace 1: its size in blocks, and its block format, which must be 512 bytes.
    if !identify(&mut controller, 0, NAMESPACE) {
        return Err(9);
    }
    let page = data();
    let blocks = u64::from_le_bytes(page[0..8].try_into().unwrap());
    let format = (page[26] & 0xf) as usize;
    let lbaf = u32::from_le_bytes(page[128 + 4 * format..132 + 4 * format].try_into().unwrap());
    if (lbaf >> 16) & 0xff != 9 || blocks == 0 {
        return Err(10);
    }
    controller.capacity = blocks;

    // The I/O queue pair: its completion queue first, with interrupts if there's a line, then its submission queue.
    let size = (ENTRIES as u32 - 1) << 16 | IO_QUEUE as u32;
    let cq = Command { opcode: ADMIN_CREATE_CQ, namespace: 0, prp1: paddr[3], cdw: [size, (interrupt as u32) << 1 | 1, 0, 0, 0, 0] };
    if !controller.admin_command(cq) {
        return Err(11);
    }
    let sq = Command { opcode: ADMIN_CREATE_SQ, namespace: 0, prp1: paddr[2], cdw: [size, (IO_QUEUE as u32) << 16 | 1, 0, 0, 0, 0] };
    if !controller.admin_command(sq) {
        return Err(12);
    }
    Ok(controller)
}

impl Controller {
    fn admin_command(&mut self, command: Command) -> bool {
        let interrupt = self.interrupt;
        submit(&mut self.admin, command, interrupt)
    }

    /// `opcode` (`NVM_READ` or `NVM_WRITE`) on `count` blocks from `first`, through the data page.
    fn transfer(&mut self, opcode: u8, first: u64, count: usize) -> bool {
        let command = Command {
            opcode,
            namespace: NAMESPACE,
            prp1: self.data_paddr,
            cdw: [first as u32, (first >> 32) as u32, count as u32 - 1, 0, 0, 0],
        };
        let interrupt = self.interrupt;
        submit(&mut self.io, command, interrupt)
    }

    fn flush(&mut self) -> bool {
        let command = Command { opcode: NVM_FLUSH, namespace: NAMESPACE, prp1: 0, cdw: [0; 6] };
        let interrupt = self.interrupt;
        submit(&mut self.io, command, interrupt)
    }
}

/// Puts `command` on `queue`, rings its doorbell, and waits for its completion. `true` if it succeeded.
fn submit(queue: &mut Queue, command: Command, interrupt: bool) -> bool {
    let id = queue.next_id;
    queue.next_id = queue.next_id.wrapping_add(1);
    let at = queue.sq + queue.tail as usize * SQE;
    let mut dwords = [0u32; 16];
    dwords[0] = command.opcode as u32 | (id as u32) << 16;
    dwords[1] = command.namespace;
    dwords[6] = command.prp1 as u32;
    dwords[7] = (command.prp1 >> 32) as u32;
    dwords[10..16].copy_from_slice(&command.cdw);
    for (i, dword) in dwords.iter().enumerate() {
        // SAFETY: the submission queue page is mapped read/write, and `at` is one of its `ENTRIES` 64-byte slots.
        unsafe { core::ptr::write_volatile((at + 4 * i) as *mut u32, *dword) };
    }
    barrier();
    queue.tail = (queue.tail + 1) % ENTRIES;
    set32(queue.sq_doorbell, queue.tail as u32);

    // Wait for its completion: the entry at the head whose phase bit matches what this pass expects.
    let entry = queue.cq + queue.head as usize * CQE;
    let dw3 = || {
        // SAFETY: the completion queue page is mapped read/write; `entry` is one of its 16-byte slots. The controller
        // writes it by DMA, so it's read volatile.
        unsafe { core::ptr::read_volatile((entry + 12) as *const u32) }
    };
    while (dw3() >> 16) & 1 != queue.phase as u32 {
        if interrupt {
            if sys::wait(NOTIFY).is_err() {
                return false;
            }
        } else {
            let _ = sys::yield_now();
        }
    }
    barrier();
    let dw3 = dw3();
    queue.head = (queue.head + 1) % ENTRIES;
    if queue.head == 0 {
        queue.phase = !queue.phase;
    }
    // Telling the controller the entry was consumed is what lowers its INTx line, so acknowledge the interrupt after.
    set32(queue.cq_doorbell, queue.head as u32);
    if interrupt {
        let _ = irq::ack(IRQ);
    }
    // The command ID it answered, and its status field: 0 is success.
    dw3 & 0xffff == id as u32 && dw3 >> 17 == 0
}

fn fail(step: usize) -> ! {
    let _ = sys::signal_with(FAILURE, step, 0);
    loop {
        let _ = sys::wait(NOTIFY);
    }
}
