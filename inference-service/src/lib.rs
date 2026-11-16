//! The inference service's decisions ([RFC-0034](../../lantern-rfcs/rfcs/0034-local-inference-and-a-file-assistant.md)):
//! which `GRANT`s it accepts, which badges are live, and which channel each is served on, with no syscalls in it, so it
//! can be tested on a host. `src/main.rs` is the program around it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use lantern_abi::frame::{status, ChannelMap};
use lantern_abi::grant::APP_SLOTS;
use lantern_abi::inference;

/// Live and revoked grants this service has minted.
pub const MAX_GRANTS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Grant {
    badge: u64,
    revoked: bool,
}

/// The grant table.
pub struct Grants {
    grants: [Option<Grant>; MAX_GRANTS],
    /// Badges count up from 1 and are never reused, so a revoked one stays dead.
    next: u64,
    channels: ChannelMap<MAX_GRANTS>,
}

/// What a `GRANT` the table accepted becomes: mint `badge`, then [`Grants::record`] it once the binder has it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Admitted {
    pub badge: u64,
    pub channel: u8,
}

impl Default for Grants {
    fn default() -> Self {
        Self { grants: [None; MAX_GRANTS], next: 1, channels: ChannelMap::default() }
    }
}

impl Grants {
    /// Whether `badge` is a grant this service made and hasn't revoked.
    pub fn live(&self, badge: u64) -> bool {
        self.grants.iter().flatten().any(|g| g.badge == badge && !g.revoked)
    }

    /// The app slot whose channel `badge` is served on, if it's live.
    pub fn channel_for(&self, badge: u64) -> Option<u8> {
        self.channels.channel_for(badge).filter(|_| self.live(badge))
    }

    /// `GRANT { object, ops, channel }`: the badge to mint, or the RFC-0019 status refusing it. Only `generate` on the
    /// one model (object 0) is ever granted, and only for an app slot's channel. `FAILED` when the table is full of live
    /// grants.
    pub fn admit(&self, object: usize, ops: usize, channel: Option<usize>) -> Result<Admitted, u16> {
        let channel = match channel {
            Some(c) if c < APP_SLOTS => c as u8,
            _ => return Err(status::INVALID),
        };
        if object != 0 || ops == 0 || ops & !(inference::GENERATE as usize) != 0 {
            return Err(status::INVALID);
        }
        let free = self.grants.iter().any(|g| g.is_none_or(|g| g.revoked));
        if !free || !self.channels.has_room(|b| !self.live(b)) {
            return Err(status::FAILED);
        }
        Ok(Admitted { badge: self.next, channel })
    }

    /// Records a badge [`admit`](Self::admit) gave, once minted. A revoked record's place is reused, else every grant
    /// would be refused once the table had filled.
    pub fn record(&mut self, admitted: Admitted) {
        let Some(free) = self.grants.iter().position(|g| g.is_none_or(|g| g.revoked)) else { return };
        self.next = admitted.badge + 1;
        self.grants[free] = Some(Grant { badge: admitted.badge, revoked: false });
        let grants = self.grants;
        self.channels.bind(admitted.badge, admitted.channel, |b| !grants.iter().flatten().any(|g| g.badge == b && !g.revoked));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(table: &mut Grants, channel: usize) -> u64 {
        let admitted = table.admit(0, inference::GENERATE as usize, Some(channel)).unwrap();
        table.record(admitted);
        admitted.badge
    }

    #[test]
    fn only_generate_on_the_model_for_an_app_slot_is_granted() {
        let table = Grants::default();
        let generate = inference::GENERATE as usize;
        assert_eq!(table.admit(0, generate, Some(1)), Ok(Admitted { badge: 1, channel: 1 }));
        assert_eq!(table.admit(1, generate, Some(1)), Err(status::INVALID), "no other object");
        assert_eq!(table.admit(0, 0, Some(1)), Err(status::INVALID), "no ops");
        assert_eq!(table.admit(0, generate | 2, Some(1)), Err(status::INVALID), "an op that doesn't exist");
        assert_eq!(table.admit(0, generate, None), Err(status::INVALID), "no channel");
        assert_eq!(table.admit(0, generate, Some(APP_SLOTS)), Err(status::INVALID), "not an app slot");
    }

    #[test]
    fn a_badge_is_served_on_its_own_channel_until_revoked_and_never_again() {
        let mut table = Grants::default();
        let a = grant(&mut table, 0);
        let b = grant(&mut table, 3);
        assert_ne!(a, b);
        assert_eq!((table.channel_for(a), table.channel_for(b)), (Some(0), Some(3)));
        assert_eq!(table.channel_for(99), None, "a badge never minted");
        assert!(table.revoke(a));
        assert!(!table.live(a) && table.channel_for(a).is_none(), "revoked at once");
        assert!(!table.revoke(a), "only once");
        // Its place is reused, never its badge.
        let c = grant(&mut table, 0);
        assert!(c > b && !table.live(a) && table.live(c));
    }

    #[test]
    fn a_full_table_refuses_until_a_grant_ends() {
        let mut table = Grants::default();
        let badges: [u64; MAX_GRANTS] = core::array::from_fn(|i| grant(&mut table, i % APP_SLOTS));
        assert_eq!(table.admit(0, inference::GENERATE as usize, Some(0)), Err(status::FAILED));
        assert!(table.revoke(badges[5]));
        assert!(table.admit(0, inference::GENERATE as usize, Some(0)).is_ok(), "a revoked place is free again");
        // Hundreds of grants and revocations later, it still grants.
        for _ in 0..500 {
            let badge = grant(&mut table, 1);
            assert!(table.live(badge));
            assert!(table.revoke(badge));
        }
    }
}
