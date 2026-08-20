//! A minimal, genuinely standalone riscv64 ELF binary — **not** part of
//! `lantern-boot`'s own build, not linked against `lantern-hal`/`lantern-kernel`
//! at all. Loaded from its own independently compiled bytes by
//! `lantern-boot`'s broker demo (`../src/broker_demo/loader.rs`), the same
//! ELF-loading mechanism `hello-service` proves (RFC-0008/ADR-0012).
//!
//! Plays the **broker** half of [RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)'s
//! confined-capability-broker demo: `Recv`s one request (a plain `Call`, no
//! payload this binary bothers reading), mints an attenuated, badged copy of
//! a capability it was granted at boot (`RESOURCE_CPTR`) via a real
//! `CNodeInvoke::Mint` `ecall`, then `Reply`s with that capability attached
//! (`tag.extra_caps == 1`) — the exact sequence
//! [`lantern_capabilities::Broker`](../../lantern-capabilities/src/lib.rs)
//! validates against a direct `KernelState`, now proven for real, issuing
//! genuine `ecall`s from confined U-mode under QEMU. `../broker-client/`
//! plays the other half.
//!
//! `SELF_CNODE_CPTR`/`ENDPOINT_CPTR`/`RESOURCE_CPTR` are conventions the
//! loader and this binary agree on without either reading the other's
//! source — the same pattern `hello-service`'s own `ENDPOINT_CPTR` documents.
//!
//! Issues raw `ecall`s directly (`lantern-hal`'s riscv64 trap entry: `mr0..mr3`
//! = `a0..a3`, tag = `a4`, syscall number = `a7`) — duplicated here rather than
//! depending on `lantern-hal`/`lantern-kernel`, same reasoning as
//! `hello-service`'s own module doc.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Root's own CNode capability, granted here at boot (`CNodeInvoke::CopyCross`
/// from the loader) so this program can invoke `Mint` on itself — the same
/// self-administration discipline `cnode.rs`'s own module doc requires
/// (`lantern-boot/src/loader.rs`'s `SELF_CNODE_CPTR` plays the identical role
/// for root).
const SELF_CNODE_CPTR: usize = 0;
/// The endpoint this program and `broker-client` both hold a capability to.
const ENDPOINT_CPTR: usize = 1;
/// The capability this program administers and grants attenuated copies of —
/// a `Notification`, granted here at boot with full rights, standing in for
/// whatever a real Phase 2 service would actually hold (a file, a key).
const RESOURCE_CPTR: usize = 2;
/// Scratch slot the minted, badged copy lands in before `Reply` transfers it.
const SCRATCH_CPTR: usize = 3;

const SYSCALL_RECV: usize = 3;
const SYSCALL_REPLY: usize = 5;
const SYSCALL_CNODE_INVOKE: usize = 9;

/// `CNodeInvoke::Mint`'s label (`lantern_kernel::cnode::LABEL_MINT`).
const LABEL_MINT: u32 = 1;

/// `lantern_kernel::cap::Rights` bit values, duplicated (see module doc).
const RIGHTS_READ: usize = 1 << 0;
const RIGHTS_WRITE: usize = 1 << 1;
const RIGHTS_GRANT: usize = 1 << 2;

/// Packs a `lantern_hal::MessageTag` the same way `MessageTag::into_raw` does
/// (`label: u32, length: u12, extra_caps: u4, flags: u16`, big-endian-most-
/// significant-first): `length`/`flags` are always `0` here, this binary never
/// needs either.
const fn pack_tag(label: u32, extra_caps: u8) -> usize {
    ((label as usize) << 32) | (((extra_caps & 0xF) as usize) << 16)
}

/// Issues one syscall via `ecall`, matching `hello-service`'s own helper
/// exactly (register mapping: `mr0..3 = a0..a3`, tag = `a4`, syscall number =
/// `a7`). This binary doesn't need to inspect its own return values —
/// `lantern-boot`'s broker-demo trap handler narrates each syscall's real
/// success/failure directly from S-mode as it dispatches (see its own module
/// doc for why: whether this program itself ever resumes afterward doesn't
/// matter to the proof).
///
/// # Safety
/// Caller upholds whatever precondition the syscall itself has.
unsafe fn syscall(num: usize, a0: usize, a1: usize, a2: usize, a3: usize, tag: usize) {
    // SAFETY: forwarded from this function's own contract; register mapping
    // matches `lantern-hal`'s riscv64 trap trampoline exactly.
    unsafe {
        asm!(
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") tag,
            in("a7") num,
            options(nostack),
        );
    }
}

#[unsafe(no_mangle)]
extern "C" fn _start(_arg0: usize) -> ! {
    // Recv the client's request. A plain Call (extra_caps == 0 both ways) --
    // this demo doesn't need a real request protocol, just a rendezvous.
    unsafe { syscall(SYSCALL_RECV, ENDPOINT_CPTR, 0, 0, 0, 0) };

    // Mint an attenuated, badged copy of the resource this broker
    // administers: READ|WRITE|GRANT (badge 99, an arbitrary distinguishing
    // value nothing checks) -- enough rights for the client to prove it's
    // real by Signal-ing it (Signal requires WRITE).
    let badge = 99usize;
    let rights = RIGHTS_READ | RIGHTS_WRITE | RIGHTS_GRANT;
    let packed = (badge << 8) | rights;
    let mint_tag = pack_tag(LABEL_MINT, 0);
    unsafe { syscall(SYSCALL_CNODE_INVOKE, SELF_CNODE_CPTR, RESOURCE_CPTR, SCRATCH_CPTR, packed, mint_tag) };

    // Reply, attaching the minted capability (tag.extra_caps == 1, mr1 names
    // the scratch slot -- mr0/a0 is unused for Reply, see abi.rs's doc).
    let reply_tag = pack_tag(0, 1);
    unsafe { syscall(SYSCALL_REPLY, 0, SCRATCH_CPTR, 111, 222, reply_tag) };

    // This program's job is done once Reply delivers -- it has nothing left
    // to do, so it never needs to resume after this point.
    loop {
        core::hint::spin_loop();
    }
}
