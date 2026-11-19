//! `lantern-inference-service` — [RFC-0034](../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md)'s
//! local inference: a language model behind a capability.
//!
//! 1. **Its model, from its own partition, signed.** It reads a model package (`lantern_sdk::model`,
//!    [RFC-0038](../../lantern-rfcs/rfcs/0038-signed-models-and-kept-audit-history.md)) from the disk's model partition
//!    through the volume (badge `MODELS`, read-only) into its heap, and checks its signature against the system's trusted
//!    publishers (`lantern_abi::publishers`), the ones the binder trusts apps from. Only a model a trusted publisher signed
//!    is parsed. A missing, unsigned, changed or malformed one leaves the service running and refusing every call
//!    `FAILED`, so an agent's call fails and is recorded, rather than the system stopping.
//! 2. **Grants, from the binder only.** `GRANT` under `GRANTER_BADGE` mints a fresh badge on this program's endpoint for
//!    object 0 (the model) and op `generate`, tied to the app slot's channel the binder names. `REVOKE` ends one at once.
//! 3. **`GENERATE`, recorded first.** Each call on a live badge is recorded in the audit log through
//!    [`policy::audited`] before the model runs: the badge, the model's publisher and digest prefix, the tokens asked for
//!    and the prompt's length. A call the log can't take doesn't run. Generation is greedy, so it's repeatable.
//!
//! It holds no store, network or console capability: it sees prompts, and can only answer the caller.
//!
//! One call at a time. While the model runs, nothing else is served, so a `REVOKE` waits until the call in progress
//! ends, at most [`inference::MAX_TOKENS`] tokens later.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::block::{self, Client, SECTOR};
use lantern_abi::frame::{self, status, Channel, Interloper};
use lantern_abi::grant::{self, Incoming, APP_SLOTS};
use lantern_inference_service::Grants;
use lantern_abi::inference;
use lantern_abi::policy::{self, AuditEntry};
use lantern_abi::publishers;
use lantern_sdk::model as package;
use lantern_abi::sys::{self, Received};
use lantern_abi::wire::Rights;
use lantern_ai_runtime::engine::{generate, Request, Sampler, Workspace};
use lantern_ai_runtime::model::{self, Model};
use lantern_ai_runtime::tokenizer::Tokenizer;

lantern_abi::entry!(run);

// Granted by the loader (`src/system/loader.rs`).
const SELF_CNODE: usize = 0;
const ENDPOINT: usize = 1;
/// Where a minted badge waits for the `Reply` that hands it to the binder.
const SCRATCH: usize = 2;
/// The policy store under `INFERENCE_WRITER_BADGE`.
const AUDIT: usize = 3;
/// The volume under its `MODELS` badge.
const VOLUME: usize = 4;
/// The shell's notification under `SYSTEM_FAILED`: a panic here is reported, not silent.
const FAILURE: usize = 5;

/// App slot `c`'s channel is at `CLIENT_VADDR + c × 4 KiB`.
const CLIENT_VADDR: usize = 0x9001_0000;
const CHANNEL_STRIDE: usize = 0x1000;
const VOLUME_VADDR: usize = 0x9002_0000;
/// Must equal `lantern_boot::launch::HEAP_VADDR`; its length, in megapages, is `arg0`'s bits 16 to 23.
const HEAP_VADDR: usize = 0x8620_0000;
const MEGAPAGE: usize = 0x20_0000;
const HEAP_SHIFT: usize = 16;


/// Grants, with the minting and the replies the decisions in `lantern_inference_service` don't make.
trait Serve {
    fn grant(&mut self, object: usize, ops: usize, channel: Option<usize>);
}

impl Serve for Grants {
    /// `GRANT`: mint `generate` on the model for the app slot's channel, and hand the badge to the binder.
    fn grant(&mut self, object: usize, ops: usize, channel: Option<usize>) {
        let admitted = match self.admit(object, ops, channel) {
            Ok(admitted) => admitted,
            Err(refused) => {
                let _ = grant::reply_status(refused);
                return;
            }
        };
        // `GRANT` too, as the store's own grants: the kernel only moves a capability that has it, so without it the reply
        // that hands this one to the binder would be refused.
        if sys::cnode::mint(SELF_CNODE, ENDPOINT, SCRATCH, admitted.badge, Rights::WRITE.union(Rights::GRANT)).is_err() {
            let _ = grant::reply_status(status::FAILED);
            return;
        }
        self.record(admitted);
        if sys::reply_with_cap(SCRATCH, [status::OK as usize, admitted.badge as usize]).is_err() {
            self.revoke(admitted.badge);
            // The binder is still waiting: answer it, rather than leave it blocked for good.
            let _ = grant::reply_status(status::FAILED);
        }
        // `Reply` copies a transferred capability; the next `GRANT` needs this slot empty.
        let _ = sys::cnode::delete(SELF_CNODE, SCRATCH);
    }
}

/// Everything that isn't the call in progress: grants and revocations, served while a client's request is open.
struct Others<'a> {
    grants: &'a mut Grants,
}

impl Interloper for Others<'_> {
    fn serve(&mut self, received: Received) {
        serve_control(self.grants, &received);
    }

    fn still_allowed(&self, badge: u64) -> bool {
        self.grants.live(badge)
    }
}

/// `GRANT`, `REVOKE`, a forged grant, or a data request that has to wait.
fn serve_control(grants: &mut Grants, received: &Received) {
    match grant::classify(received) {
        Incoming::Grant { object, ops, channel, .. } => grants.grant(object, ops, channel),
        Incoming::Revoke { badge } => {
            let status = if grants.revoke(badge) { status::OK } else { status::INVALID };
            let _ = grant::reply_status(status);
        }
        Incoming::ForgedGrant => {
            let _ = grant::reply_status(status::ACCESS);
        }
        Incoming::Data => frame::reply_busy(),
    }
}

/// The model, ready to run.
struct Engine {
    /// The model's BLAKE3 digest's first 4 bytes, and its publisher's key's first 2: how the audit log names it.
    id: u32,
    publisher: u16,
    model: Model<'static>,
    tokenizer: Tokenizer<'static>,
    workspace: Workspace<'static>,
    tokens: &'static mut [u32],
}

/// Why there's no model, for nothing but a debugger: every call is refused `FAILED` either way.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum NoModel {
    Unreadable,
    TooLarge,
    /// Not a model package, or no trusted publisher signed it.
    Untrusted,
    Malformed(model::ModelError),
    NoRoom,
}

/// Carves `n` `T`s, aligned, from the front of `rest`.
fn carve<T: Copy>(rest: &mut &'static mut [u8], n: usize, zero: T) -> Option<&'static mut [T]> {
    let align = core::mem::align_of::<T>();
    let pad = rest.as_ptr().align_offset(align);
    let bytes = n.checked_mul(core::mem::size_of::<T>())?.checked_add(pad)?;
    if rest.len() < bytes {
        return None;
    }
    let (head, tail) = core::mem::take(rest).split_at_mut(bytes);
    *rest = tail;
    let ptr = head[pad..].as_mut_ptr().cast::<T>();
    // SAFETY: `ptr` is aligned for `T`, `n` of them fit in `head[pad..]`, which nothing else borrows from here on, and
    // `T: Copy` has no drop; each element is written before the slice is returned.
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, n) };
    slice.fill(zero);
    Some(slice)
}

/// Reads the model package into the heap, checks a trusted publisher signed it, and sets the engine up after it.
fn load(volume: &mut Client, heap: &'static mut [u8]) -> Result<Engine, NoModel> {
    let mut header = [0u8; SECTOR];
    volume.read(0, &mut header).map_err(|_| NoModel::Unreadable)?;
    let len = package::package_len(&header[..package::MODEL_OFFSET]).map_err(|_| NoModel::Untrusted)?;
    let read_len = len.div_ceil(block::MAX_BYTES) * block::MAX_BYTES;
    if read_len > heap.len() {
        return Err(NoModel::TooLarge);
    }
    let (file, mut rest) = heap.split_at_mut(read_len.next_multiple_of(64));
    for (i, chunk) in file[..read_len].chunks_mut(block::MAX_BYTES).enumerate() {
        volume.read((i * block::MAX_SECTORS) as u64, chunk).map_err(|_| NoModel::Unreadable)?;
    }
    let file: &'static [u8] = &file[..len];
    let package = package::decode_model(file).map_err(|_| NoModel::Untrusted)?;
    let publisher = publishers::TRUSTED.iter().find(|key| package.verify(key).is_ok()).ok_or(NoModel::Untrusted)?;
    let digest = lantern_crypto::hash::hash(package.model);
    let d = digest.as_bytes();
    let (id, publisher) = (u32::from_be_bytes([d[0], d[1], d[2], d[3]]), publishers::short(publisher));
    let file = package.model;
    let model = model::parse(file).map_err(NoModel::Malformed)?;
    let c = model.config;
    let (floats, bytes) = Workspace::sizes(&c);
    let floats = carve(&mut rest, floats, 0f32).ok_or(NoModel::NoRoom)?;
    let bytes = carve(&mut rest, bytes, 0i8).ok_or(NoModel::NoRoom)?;
    let offsets = carve(&mut rest, c.vocab_size, 0u32).ok_or(NoModel::NoRoom)?;
    let sorted = carve(&mut rest, c.vocab_size, 0u32).ok_or(NoModel::NoRoom)?;
    let tokens = carve(&mut rest, c.seq_len, 0u32).ok_or(NoModel::NoRoom)?;
    let workspace = Workspace::new(&c, floats, bytes).ok_or(NoModel::NoRoom)?;
    let tokenizer =
        Tokenizer::new(model.tokenizer, c.vocab_size, offsets, sorted).map_err(NoModel::Malformed)?;
    Ok(Engine { id, publisher, model, tokenizer, workspace, tokens })
}

/// `GENERATE` on `request`: the continuation into `reply`. `INVALID` for a request over the limits or a prompt that fills
/// the model's context, `FAILED` with no model.
fn serve_generate(engine: Option<&mut Engine>, request: &[u8], reply: &mut [u8]) -> (u16, usize) {
    let Some((max_tokens, prompt)) = inference::decode_request(request) else { return (status::INVALID, 0) };
    let Some(e) = engine else { return (status::FAILED, 0) };
    let mut len = 0;
    let request = Request { prompt, max_tokens, sampler: Sampler::GREEDY };
    let emit = |piece: &[u8]| {
        let Some(dest) = reply.get_mut(len..len + piece.len()) else { return false };
        dest.copy_from_slice(piece);
        len += piece.len();
        true
    };
    match generate(&e.model, &e.tokenizer, &mut e.workspace, e.tokens, request, emit) {
        Ok(_) => (status::OK, len),
        Err(_) => (status::INVALID, 0),
    }
}

fn run(arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE);
    let audited = arg0 & grant::AUDITED != 0;
    let heap_len = ((arg0 >> HEAP_SHIFT) & 0xff) * MEGAPAGE;
    // SAFETY: the loader mapped `heap_len` bytes read/write at HEAP_VADDR (`ProgramSpec::heap_megapages`), this
    // program's alone, before its first instruction; only `load` uses it, once.
    let heap: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(HEAP_VADDR as *mut u8, heap_len) };
    // SAFETY: the loader mapped the channel shared with the volume read/write at VOLUME_VADDR.
    let mut volume = Client { channel: unsafe { Channel::new(VOLUME, VOLUME_VADDR as *mut u8) } };
    let mut engine = load(&mut volume, heap).ok();

    let mut grants = Grants::default();
    // SAFETY: the loader mapped each app slot's channel read/write, one page apart, from CLIENT_VADDR, for good.
    let mut channels: [Channel; APP_SLOTS] =
        core::array::from_fn(|c| unsafe { Channel::new(ENDPOINT, (CLIENT_VADDR + c * CHANNEL_STRIDE) as *mut u8) });
    let mut request = [0u8; inference::HEADER + inference::MAX_PROMPT];
    let mut reply = [0u8; inference::MAX_REPLY];
    loop {
        let Ok(received) = sys::recv(ENDPOINT) else { continue };
        if grant::classify(&received) != Incoming::Data {
            serve_control(&mut grants, &received);
            continue;
        }
        let badge = received.badge;
        let Some(channel) = grants.channel_for(badge) else {
            // A badge this service never tied to a channel, or one revoked: nothing can be written back.
            let _ = sys::reply_with_label(status::ACCESS as u32, [0, 0, 0]);
            continue;
        };
        let channel = &mut channels[channel as usize];
        let Ok((op, len)) = channel.recv_request(received, &mut request, &mut Others { grants: &mut grants }) else { continue };
        let (outcome, reply_len) = if op != inference::OP_GENERATE {
            (status::INVALID, 0)
        } else if !grants.live(badge) {
            // Revoked while its request arrived.
            (status::ACCESS, 0)
        } else {
            let prompt_len = len.saturating_sub(inference::HEADER);
            let max_tokens = request.get(..2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as usize);
            // Which model: its publisher, and its digest's prefix. With none loaded, both are 0.
            let (id, publisher) = engine.as_ref().map_or((0, 0), |e| (e.id, e.publisher));
            let using = AuditEntry {
                ops: inference::GENERATE,
                object: publisher,
                subject: [badge, inference::audit_subject(id, max_tokens, prompt_len)],
                ..AuditEntry::default()
            };
            let mut run = || serve_generate(engine.as_mut(), &request[..len], &mut reply);
            if audited {
                policy::audited(AUDIT, &using, run).unwrap_or((status::FAILED, 0))
            } else {
                run()
            }
        };
        let _ = channel.reply(outcome, &reply[..reply_len], badge, &mut Others { grants: &mut grants });
    }
}
