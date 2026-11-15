//! The filter accept list and the resolving list: which peers advertising
//! accepts, and the keys that resolve their private addresses.

use crate::{crypto, pdu::Peer};

/// Entries of the filter accept list.
pub const FILTER_LIST_SIZE: usize = 4;
/// Peers in the resolving list.
pub const RESOLVING_LIST_SIZE: usize = 2;

/// The filter accept list.
#[derive(Clone, Copy)]
pub struct FilterList {
    /// Entries.
    entries: [Option<Peer>; FILTER_LIST_SIZE],
}

impl FilterList {
    /// Adds a device. Returns false if the list is full.
    #[inline]
    pub fn add(&mut self, peer: Peer) -> bool {
        if self.contains(peer) {
            return true;
        }
        self.entries.iter_mut().find(|entry| entry.is_none()).is_some_and(|entry| {
            *entry = Some(peer);
            true
        })
    }

    /// Removes all devices.
    #[inline]
    pub const fn clear(&mut self) { self.entries = [None; FILTER_LIST_SIZE]; }

    /// Whether the list holds a device.
    #[inline]
    #[must_use = "the membership is only checked"]
    pub fn contains(&self, peer: Peer) -> bool { self.entries.contains(&Some(peer)) }

    /// An empty list.
    #[inline]
    #[must_use = "the list is only created"]
    pub const fn new() -> Self { Self { entries: [None; FILTER_LIST_SIZE] } }

    /// Removes a device.
    #[inline]
    pub fn remove(&mut self, peer: Peer) {
        for entry in &mut self.entries {
            if *entry == Some(peer) {
                *entry = None;
            }
        }
    }
}

impl Default for FilterList {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Privacy state belonging to one peer identity.
#[derive(Clone, Copy)]
struct ResolvingEntry {
    /// Device privacy accepts identity addresses as well as RPAs.
    device: bool,
    /// Peer identity resolving key.
    irk:    [u8; 16],
    /// Local identity resolving key for this peer.
    local:  [u8; 16],
    /// Identity address.
    peer:   Peer,
}

/// Peers whose resolvable private addresses are resolved to their identity
/// address, with their identity resolving keys.
#[derive(Clone, Copy)]
pub struct ResolvingList {
    /// Identity address and key of each peer.
    entries: [Option<ResolvingEntry>; RESOLVING_LIST_SIZE],
}

impl ResolvingList {
    /// Whether an identity address is acceptable under its privacy mode.
    pub(super) fn accepts_identity(&self, peer: Peer) -> bool {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.peer == peer)
            .is_none_or(|entry| entry.device || entry.irk == [0; 16])
    }

    /// Adds or replaces the key of `identity`. Returns false if the list is
    /// full.
    #[inline]
    pub fn add(&mut self, identity: Peer, irk: [u8; 16]) -> bool { self.add_keys(identity, irk, [0; 16]) }

    /// Stores both keys, preserving the per-peer privacy mode.
    #[inline]
    pub fn add_keys(&mut self, identity: Peer, irk: [u8; 16], local: [u8; 16]) -> bool {
        self.remove(identity);
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else { return false };
        *slot = Some(ResolvingEntry { peer: identity, irk, local, device: false });
        true
    }

    /// Whether a new entry or a replacement fits without changing the list.
    pub(crate) fn can_add(&self, peer: Peer) -> bool {
        self.entries.iter().any(|entry| entry.is_none_or(|listed| listed.peer == peer))
    }

    /// Removes every peer, overwriting their keys.
    #[inline]
    pub fn clear(&mut self) {
        for slot in &mut self.entries {
            Self::forget(slot);
        }
    }

    /// Overwrites the key in `slot` and empties it.
    fn forget(slot: &mut Option<ResolvingEntry>) {
        if let Some(entry) = slot.as_mut() {
            crypto::wipe(&mut entry.irk);
            crypto::wipe(&mut entry.local);
        }
        *slot = None;
    }

    /// The identity address of `address`: the identity whose key generated
    /// it, if it is a resolvable private address of a listed peer, as
    /// `resolves` decides (on the chip [`crypto::resolves`]).
    pub(super) fn identity<Resolves>(&self, address: Peer, resolves: Resolves) -> Option<Peer>
    where
        Resolves: Fn([u8; 16], [u8; 6]) -> bool,
    {
        if !address.random {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.irk != [0; 16] && resolves(entry.irk, address.address))
            .map(|entry| entry.peer)
    }

    /// Whether no peer is listed.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool { self.entries.iter().all(Option::is_none) }

    /// Local key associated with the directed peer or first listed peer.
    #[inline]
    #[must_use = "the key is only read"]
    pub fn local_key(&self, peer: Option<Peer>) -> Option<[u8; 16]> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| peer.is_none_or(|target| target == entry.peer) && entry.local != [0; 16])
            .map(|entry| entry.local)
    }

    /// An empty list.
    #[inline]
    #[must_use = "the list is only created"]
    pub const fn new() -> Self { Self { entries: [None; RESOLVING_LIST_SIZE] } }

    /// The identity resolving key of the peer `identity`, if the list holds
    /// a non-zero one: directed advertising from a private address targets a
    /// resolvable private address made with it (Core, Vol 6, Part B, 6.2.2).
    /// The copy holds the key and is the caller's to wipe.
    #[cfg(feature = "directed-advertising")]
    #[inline]
    #[must_use = "the key is only read"]
    pub fn peer_key(&self, identity: Peer) -> Option<[u8; 16]> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.peer == identity && entry.irk != [0; 16])
            .map(|entry| entry.irk)
    }

    /// Removes `identity`.
    #[inline]
    pub fn remove(&mut self, identity: Peer) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| entry.peer == identity) {
                Self::forget(slot);
            }
        }
    }

    /// Changes the privacy mode of an existing identity.
    #[inline]
    pub fn set_mode(&mut self, peer: Peer, device: bool) -> bool {
        let Some(entry) = self.entries.iter_mut().flatten().find(|entry| entry.peer == peer) else { return false };
        entry.device = device;
        true
    }
}

impl Default for ResolvingList {
    #[inline]
    fn default() -> Self { Self::new() }
}
