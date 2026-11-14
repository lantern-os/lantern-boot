//! A minimal, genuinely standalone riscv64 ELF binary — loaded from its own
//! independently compiled bytes by `lantern-boot`'s store demo
//! (`../src/store_demo/loader.rs`).
//!
//! Runs a **real, confined [`lantern_filesystem::Store`]** — the RFC-0018/
//! ADR-0022 Part 1 confined-service port, applied to the store for the first
//! time (`../keystore-service/` already proved the pattern for `Keystore`).
//! This is the first demo program with *two* distinct IPC relationships at
//! once, exactly the "middle service" shape ADR-0022 describes:
//!
//! 1. **A keystore *client* leg** — registers with `../keystore-service/`
//!    exactly the way `../keystore-client/` does (`Call`, registering its own
//!    reply destination), receiving a badge scoped to ENCRYPT|DECRYPT on that
//!    demo's one AEAD key. This badge/`Channel` pair becomes a
//!    [`lantern_filesystem::cipher::ChannelCipher`] — `Store`'s own AEAD
//!    operations reach the key over *real IPC*, not a direct `&Keystore`
//!    reference, closing the gap `lantern-filesystem/STATUS.md` named after
//!    the `Cipher` trait redesign.
//! 2. **A store *service* leg** — a live `Broker::mint`+`grant_via_reply`
//!    file-access grant round for its own client (`../store-client/`), then
//!    an RFC-0019/ADR-0024 READ/WRITE `Recv` loop over a *second*,
//!    independent shared `Frame` — `lantern_filesystem::wire::handle_request`
//!    does the actual parsing/dispatch (reviewed and unit-tested in
//!    `lantern-filesystem` itself, not re-derived here).
//!
//! Two shared `Frame`s, two different virtual addresses in this program's own
//! single VSpace (`KS_FRAME_VADDR`/`CLIENT_FRAME_VADDR`) — `Channel` has no
//! concept of "the" frame, each instance just wraps whichever `(endpoint,
//! frame)` pair it was constructed against.
//!
//! The [`grant::BINDER_LAUNCHED`] `arg0` flag drops the first-caller file grant: this
//! instance then grants only over [RFC-0020](../../lantern-rfcs/rfcs/0020-launch-binder.md)'s
//! `GRANT`, from the launch binder. Its own client leg to `keystore-service` is
//! launcher-fixed infrastructure and stays as it is. In every mode, a `GRANT` from anyone
//! else is refused `ACCESS`.
//!
//! The [`grant::AUDITED`] flag ([RFC-0025](../../lantern-rfcs/rfcs/0025-audit-log-service-operations.md))
//! makes this instance record every use of a file grant in the policy store's audit log, through
//! [`policy::audited`], before it runs, and its own first-caller grant before delivering it. Each
//! `WRITE` and `READ` then reaches `keystore-service`, which records its own `ENCRYPT` and `DECRYPT`
//! under this store's badge there.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::{self, status, Channel, ChannelMap, Interloper};
use lantern_abi::grant::{self, Incoming};
use lantern_abi::policy::{self, event, AuditEntry};
use lantern_abi::sys::{self, Received};
use lantern_capabilities::Abi;
use lantern_filesystem::cipher::ChannelCipher;
use lantern_filesystem::{wire, FileId, FileOps, Store};

lantern_abi::entry!(run);

/// Root's own CNode capability, granted at boot so this store can invoke
/// `Mint` on itself — matches `keystore-service`'s identical convention.
const SELF_CNODE_CPTR: usize = 0;
/// The endpoint this program and `keystore-service` both hold a capability
/// to — this program's *client* leg.
const KS_ENDPOINT_CPTR: usize = 1;
/// Where `keystore-service`'s granted, badged capability lands — this
/// program's actual `Channel` to it afterward.
const KS_DEST_CPTR: usize = 2;
/// The endpoint this program and `store-client` both hold a capability to —
/// this program's *service* leg, also `Broker::mint`'s attenuation source
/// (see `keystore-service`'s module doc for why the retained authority and
/// the mint source are the same capability).
const CLIENT_ENDPOINT_CPTR: usize = 3;
/// Scratch slot the minted, badged file-access copy lands in before `Reply`
/// transfers it to `store-client`.
const SCRATCH_CPTR: usize = 4;
/// The policy store's endpoint under `STORE_WRITER_BADGE`, when launched [`grant::AUDITED`].
const AUDIT_CPTR: usize = 5;
/// Where the loader mapped this program's half of the `keystore-service`
/// shared `Frame` — must match `keystore-service`'s own `FRAME_VADDR`.
const KS_FRAME_VADDR: usize = 0x9000_0000;
/// Where the loader mapped this program's half of the `store-client` shared
/// `Frame` — a *different* virtual address in this program's own VSpace than
/// [`KS_FRAME_VADDR`] (two independent physical Frames, two mappings) — must
/// match `store-client`'s own `FRAME_VADDR`.
const CLIENT_FRAME_VADDR: usize = 0x9001_0000;

/// With [`grant::MANY_CLIENTS`] ([RFC-0029](../../lantern-rfcs/rfcs/0029-a-confined-launcher.md)): one client channel
/// per app slot, `CHANNEL_STRIDE` apart from [`CLIENT_FRAME_VADDR`]. Each badge is served on the channel its `GRANT` named,
/// and only there.
const CHANNEL_STRIDE: usize = 0x1000;
/// Live grants with a channel. Matches `lantern_filesystem`'s own grant capacity.
const MAPPED_GRANTS: usize = 32;

/// Large enough for this demo's small READ/WRITE payloads — see
/// `keystore-service`'s identical constant for the general sizing rule.
const REQUEST_CAP: usize = 256;

fn run(arg0: usize) -> ! {
    // Client leg: register with keystore-service, registering our own
    // reply-leg destination (broker-client's exact convention).
    let _ = sys::call_with_reply_slot(KS_ENDPOINT_CPTR, KS_DEST_CPTR, [0, 0]);
    // SAFETY: the loader mapped `KS_FRAME_VADDR..+FRAME_LEN` read/write into
    // this program's own VSpace before its first instruction ran
    // (`store_demo/loader.rs`'s first `map_shared_frame` call).
    let mut ks_channel = unsafe { Channel::new(KS_DEST_CPTR, KS_FRAME_VADDR as *mut u8) };

    let mut store = Store::new(SELF_CNODE_CPTR);
    let file = store.create().expect("fresh Store always has room for its first file");

    let mut backend = Abi;
    let audited = arg0 & grant::AUDITED != 0;
    // Service leg: one client Call's, registering its own reply-leg
    // destination; grant it READ|WRITE on the one file this demo creates.
    if arg0 & grant::BINDER_LAUNCHED == 0 {
        let _ = sys::recv(CLIENT_ENDPOINT_CPTR);
        let ops = FileOps::READ.union(FileOps::WRITE);
        // Recorded after minting, since the badge is the record, and before delivering: an unrecorded
        // grant never reaches its holder. It is withdrawn instead, and the caller told, and this service
        // goes on serving, refusing everything, rather than stopping every program with it.
        let minted = store.request_file_access(&mut backend, file, ops, CLIENT_ENDPOINT_CPTR, SCRATCH_CPTR).ok();
        let recorded = minted.filter(|&badge| {
            let entry = AuditEntry {
                event: event::SERVICE_GRANTED,
                object: file.raw(),
                ops: ops.bits(),
                subject: [badge, 0],
                ..AuditEntry::default()
            };
            !audited || policy::append(AUDIT_CPTR, &entry) == Ok(status::OK)
        });
        let delivered = recorded.is_some_and(|_| store.deliver_grant_via_reply(&mut backend, SCRATCH_CPTR, (0, 0)).is_ok());
        if !delivered {
            if let Some(badge) = minted {
                let _ = store.revoke_access(badge);
            }
            let _ = grant::reply_status(status::FAILED);
        }
        // `Reply` copies a transferred capability; a later `GRANT` needs this slot empty.
        let _ = sys::cnode::delete(SELF_CNODE_CPTR, SCRATCH_CPTR);
    }

    // SAFETY: as above, for `CLIENT_FRAME_VADDR` (the loader's *second*
    // `map_shared_frame` call).
    // With `MANY_CLIENTS`, one per app slot; otherwise only the first exists, and only it is used.
    let many = arg0 & grant::MANY_CLIENTS != 0;
    let mut channels = ChannelMap::<MAPPED_GRANTS>::default();
    // SAFETY: as above, for each channel the loader mapped; an unmapped one is never reached.
    let mut all: [Channel; grant::APP_SLOTS] = core::array::from_fn(|c| unsafe {
        Channel::new(CLIENT_ENDPOINT_CPTR, (CLIENT_FRAME_VADDR + c * CHANNEL_STRIDE) as *mut u8)
    });
    loop {
        let Ok(received) = sys::recv(CLIENT_ENDPOINT_CPTR) else { continue };
        match grant::classify(&received) {
            Incoming::Data => {
                let Some(channel) = (if many { channels.channel_for(received.badge) } else { Some(0) }) else {
                    // A badge this store never tied to a channel: nothing can be written back, so the label refuses it.
                    let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
                    continue;
                };
                let client_channel = &mut all[channel as usize];
                let mut request = [0u8; REQUEST_CAP];
                let mut others = Others { store: &mut store, backend: &mut backend, channels: &mut channels, many };
                if let Ok((op, len)) = client_channel.recv_request(received, &mut request, &mut others) {
                    // The keystore-service leg: Store's own encrypt/decrypt reach
                    // the AEAD key over real IPC, not a direct &Keystore call.
                    let mut cipher = ChannelCipher::new(&mut ks_channel);
                    let mut reply = [0u8; REQUEST_CAP];
                    // A badge this store never minted names no grant, and `handle_request` refuses it.
                    let granted_file = store.file_for_badge(received.badge);
                    let mut handle =
                        || wire::handle_request(&mut store, &mut cipher, received.badge, op, &request[..len], &mut reply);
                    let (status, reply_len) = match granted_file {
                        Some(file) if audited => {
                            let using = AuditEntry {
                                object: file.raw(),
                                ops: op_bit(op),
                                subject: [received.badge, len as u64],
                                ..AuditEntry::default()
                            };
                            policy::audited(AUDIT_CPTR, &using, handle).unwrap_or((status::FAILED, 0))
                        }
                        _ => handle(),
                    };
                    let mut others = Others { store: &mut store, backend: &mut backend, channels: &mut channels, many };
                    let _ = client_channel.reply(status, &reply[..reply_len], received.badge, &mut others);
                }
                // `recv_request`'s `Err` path has already sent `INVALID` itself.
            }
            _ => Others { store: &mut store, backend: &mut backend, channels: &mut channels, many }.serve(received),
        }
    }
}

/// Everything that isn't the data client: served the same way whether this program is idle or
/// waiting on a client's next chunk (RFC-0021). All of it stays off the shared `Frame`.
struct Others<'a> {
    store: &'a mut Store,
    backend: &'a mut Abi,
    channels: &'a mut ChannelMap<MAPPED_GRANTS>,
    many: bool,
}

impl Interloper for Others<'_> {
    fn serve(&mut self, received: Received) {
        match grant::classify(&received) {
            Incoming::Grant { object, ops, channel } => {
                let channel = match (self.many, channel) {
                    (false, _) => None,
                    (true, Some(c)) if c < grant::APP_SLOTS => Some(c as u8),
                    (true, _) => {
                        let _ = grant::reply_status(status::INVALID);
                        return;
                    }
                };
                serve_grant(self.store, self.backend, self.channels, object, ops, channel)
            }
            Incoming::Revoke { badge } => {
                let status = if self.store.revoke_access(badge).is_ok() { status::OK } else { status::INVALID };
                let _ = grant::reply_status(status);
            }
            Incoming::ForgedGrant => {
                let _ = grant::reply_status(status::ACCESS);
            }
            Incoming::Data => frame::reply_busy(),
        }
    }

    fn still_allowed(&self, badge: u64) -> bool {
        !self.store.is_revoked(badge)
    }
}

/// The [`FileOps`] bit a wire op uses, which is what the audit log records. 0 for an op that doesn't exist,
/// which `handle_request` refuses as `INVALID`, and the log then shows as `USE_FAILED`.
fn op_bit(op: u16) -> u8 {
    match op {
        wire::OP_READ => FileOps::READ.bits(),
        wire::OP_WRITE => FileOps::WRITE.bits(),
        _ => 0,
    }
}

/// RFC-0020's `GRANT`: mint exactly `ops` on `object` and hand the badge back. The
/// checks that matter (the file exists and isn't destroyed) are
/// `request_file_access`'s own.
fn serve_grant(
    store: &mut Store,
    backend: &mut Abi,
    channels: &mut ChannelMap<MAPPED_GRANTS>,
    object: usize,
    ops: usize,
    channel: Option<u8>,
) {
    let request = u16::try_from(object)
        .ok()
        .zip(u8::try_from(ops).ok().filter(|&bits| bits != 0).and_then(FileOps::from_bits));
    let Some((object, ops)) = request else {
        let _ = grant::reply_status(status::INVALID);
        return;
    };
    // Room for the badge's channel first, so a badge is never delivered without one.
    if channel.is_some() && !channels.has_room(|b| store.is_revoked(b)) {
        let _ = grant::reply_status(status::FAILED);
        return;
    }
    let granted = store.request_file_access(backend, FileId::from_raw(object), ops, CLIENT_ENDPOINT_CPTR, SCRATCH_CPTR).and_then(|badge| {
        if let Some(c) = channel {
            channels.bind(badge, c, |b| store.is_revoked(b));
        }
        store.deliver_grant_via_reply(backend, SCRATCH_CPTR, (status::OK as usize, badge as usize))
    });
    if granted.is_err() {
        let _ = grant::reply_status(status::INVALID);
    }
    // `Reply` copies a transferred capability; the next `GRANT` needs this slot empty.
    let _ = sys::cnode::delete(SELF_CNODE_CPTR, SCRATCH_CPTR);
}
