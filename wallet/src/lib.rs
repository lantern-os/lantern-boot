//! The wallet's decisions ([RFC-0035](../../lantern-rfcs/rfcs/0035-pairwise-network-identities.md)), with no syscalls in
//! them, so they can be tested on a host: the contexts it knows, its grant table, what it has presented, and its sealed
//! root's format. `src/main.rs` is the program around it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use lantern_abi::frame::status;
use lantern_abi::grant::APP_SLOTS;
use lantern_abi::identity::{self, Presented};

pub use lantern_abi::identity::{context, Context, CONTEXTS};

/// The Noise prologue: both sides must agree on it, so a session can't be mistaken for another protocol's.
pub const PROLOGUE: &[u8] = b"lantern-identity-v1";

/// Live and revoked grants.
pub const MAX_GRANTS: usize = 32;
/// Each grant's session talks from its own port, `PORT_BASE + its place in the table`.
pub const PORT_BASE: u16 = 40000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Grant {
    pub badge: u64,
    pub principal: u64,
    pub context: u16,
    pub channel: u8,
    pub revoked: bool,
}

/// The grant table.
pub struct Grants {
    grants: [Option<Grant>; MAX_GRANTS],
    next: u64,
}

impl Default for Grants {
    fn default() -> Self {
        Self { grants: [None; MAX_GRANTS], next: 1 }
    }
}

impl Grants {
    /// The live grant `badge` names, and its place in the table.
    pub fn live(&self, badge: u64) -> Option<(usize, Grant)> {
        self.grants.iter().enumerate().find_map(|(i, g)| g.filter(|g| g.badge == badge && !g.revoked).map(|g| (i, g)))
    }

    /// `GRANT { object, ops, channel, principal }`: the place and badge for a new grant, or the status refusing it. Only
    /// `connect` on a context this wallet knows, for an app slot's channel, for a named app.
    pub fn admit(&self, object: usize, ops: usize, channel: Option<usize>, principal: u64) -> Result<(usize, Grant), u16> {
        let channel = match channel {
            Some(c) if c < APP_SLOTS => c as u8,
            _ => return Err(status::INVALID),
        };
        let context = u16::try_from(object).ok().and_then(context).ok_or(status::INVALID)?;
        if ops != identity::CONNECT as usize || principal == lantern_abi::provenance::NONE {
            return Err(status::INVALID);
        }
        // A revoked record's place is reused, else every grant would be refused once the table had filled.
        let place = self.grants.iter().position(|g| g.is_none_or(|g| g.revoked)).ok_or(status::FAILED)?;
        Ok((place, Grant { badge: self.next, principal, context: context.id, channel, revoked: false }))
    }

    /// Records a grant [`admit`](Self::admit) gave, once its badge is minted.
    pub fn record(&mut self, place: usize, grant: Grant) {
        self.next = grant.badge + 1;
        self.grants[place] = Some(grant);
    }

    /// `REVOKE`: `true` if `badge` was live, and isn't now.
    pub fn revoke(&mut self, badge: u64) -> bool {
        match self.grants.iter_mut().flatten().find(|g| g.badge == badge && !g.revoked) {
            Some(g) => {
                g.revoked = true;
                true
            }
            None => false,
        }
    }
}

/// What the wallet has presented, for the shell's `identities`.
pub const MAX_PRESENTED: usize = 32;

#[derive(Default)]
pub struct Log {
    entries: [Option<Presented>; MAX_PRESENTED],
}

impl Log {
    /// One more session as `(principal, context)` with the key whose prefix is `key`. When full, the first entry gives way.
    pub fn record(&mut self, principal: u64, context: u16, key: u32) {
        if let Some(p) = self.entries.iter_mut().flatten().find(|p| p.principal == principal && p.context == context) {
            p.sessions = p.sessions.saturating_add(1);
            return;
        }
        let entry = Presented { principal, context, key, sessions: 1 };
        match self.entries.iter_mut().find(|e| e.is_none()) {
            Some(free) => *free = Some(entry),
            None => {
                self.entries.rotate_left(1);
                self.entries[MAX_PRESENTED - 1] = Some(entry);
            }
        }
    }

    pub fn get(&self, index: usize) -> Option<Presented> {
        self.entries.get(index).copied().flatten()
    }
}

/// The sealed root on the wallet's partition: `MAGIC`, the nonce, the tag, then the root, encrypted under the wallet's
/// keystore key with [`ROOT_AAD`].
pub const MAGIC: &[u8; 8] = b"LWALLET1";
pub const ROOT_AAD: &[u8] = b"lantern-wallet-root-v1";
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SEALED_LEN: usize = 8 + NONCE_LEN + TAG_LEN + 32;

/// What a sector holds: nothing yet (all zero), a sealed root, or something else, which the wallet never overwrites.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sector {
    Empty,
    Sealed { nonce: [u8; NONCE_LEN], tag: [u8; TAG_LEN], ciphertext: [u8; 32] },
    Unknown,
}

pub fn read_sector(sector: &[u8]) -> Sector {
    if sector.iter().all(|&b| b == 0) {
        return Sector::Empty;
    }
    if sector.len() < SEALED_LEN || &sector[..8] != MAGIC {
        return Sector::Unknown;
    }
    Sector::Sealed {
        nonce: sector[8..8 + NONCE_LEN].try_into().unwrap(),
        tag: sector[8 + NONCE_LEN..8 + NONCE_LEN + TAG_LEN].try_into().unwrap(),
        ciphertext: sector[8 + NONCE_LEN + TAG_LEN..SEALED_LEN].try_into().unwrap(),
    }
}

pub fn write_sector(nonce: &[u8; NONCE_LEN], tag: &[u8; TAG_LEN], ciphertext: &[u8; 32], sector: &mut [u8]) {
    sector.fill(0);
    sector[..8].copy_from_slice(MAGIC);
    sector[8..8 + NONCE_LEN].copy_from_slice(nonce);
    sector[8 + NONCE_LEN..8 + NONCE_LEN + TAG_LEN].copy_from_slice(tag);
    sector[8 + NONCE_LEN + TAG_LEN..SEALED_LEN].copy_from_slice(ciphertext);
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECT: usize = identity::CONNECT as usize;

    #[test]
    fn only_connect_to_a_known_context_for_a_named_app_on_an_app_slot_is_granted() {
        let g = Grants::default();
        let (place, grant) = g.admit(1, CONNECT, Some(2), 0xabc).unwrap();
        assert_eq!((place, grant.badge, grant.context, grant.channel, grant.principal), (0, 1, 1, 2, 0xabc));
        assert_eq!(g.admit(9, CONNECT, Some(0), 1), Err(status::INVALID), "an unknown context");
        assert_eq!(g.admit(1, 2, Some(0), 1), Err(status::INVALID), "another op");
        assert_eq!(g.admit(1, CONNECT, None, 1), Err(status::INVALID), "no channel");
        assert_eq!(g.admit(1, CONNECT, Some(APP_SLOTS), 1), Err(status::INVALID), "not an app slot");
        assert_eq!(g.admit(1, CONNECT, Some(0), 0), Err(status::INVALID), "no principal: nothing to derive from");
    }

    #[test]
    fn a_revoked_grant_is_dead_at_once_and_its_place_is_reused_never_its_badge() {
        let mut g = Grants::default();
        let mut badges = vec![];
        for i in 0..MAX_GRANTS {
            let (place, grant) = g.admit(1, CONNECT, Some(i % APP_SLOTS), 7).unwrap();
            g.record(place, grant);
            badges.push(grant.badge);
        }
        assert_eq!(g.admit(1, CONNECT, Some(0), 7), Err(status::FAILED), "full");
        assert!(g.revoke(badges[3]) && !g.revoke(badges[3]));
        assert_eq!(g.live(badges[3]), None);
        let (place, grant) = g.admit(2, CONNECT, Some(0), 7).unwrap();
        assert_eq!(place, 3);
        assert!(!badges.contains(&grant.badge));
        g.record(place, grant);
        assert_eq!(g.live(grant.badge).map(|(i, _)| i), Some(3));
    }

    #[test]
    fn the_log_counts_sessions_per_app_and_context() {
        let mut log = Log::default();
        log.record(1, 1, 0xaa);
        log.record(1, 1, 0xaa);
        log.record(1, 2, 0xbb);
        log.record(2, 1, 0xcc);
        assert_eq!(log.get(0), Some(Presented { principal: 1, context: 1, key: 0xaa, sessions: 2 }));
        assert_eq!(log.get(1).unwrap().context, 2);
        assert_eq!(log.get(2).unwrap().principal, 2);
        assert_eq!(log.get(3), None);
    }

    #[test]
    fn a_sealed_root_reads_back_and_anything_else_is_left_alone() {
        let mut sector = [0u8; 512];
        assert_eq!(read_sector(&sector), Sector::Empty);
        write_sector(&[1; NONCE_LEN], &[2; TAG_LEN], &[3; 32], &mut sector);
        assert_eq!(read_sector(&sector), Sector::Sealed { nonce: [1; NONCE_LEN], tag: [2; TAG_LEN], ciphertext: [3; 32] });
        sector[0] = b'X';
        assert_eq!(read_sector(&sector), Sector::Unknown);
        assert_eq!(read_sector(&[0xff; 512]), Sector::Unknown);
    }
}
