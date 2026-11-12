//! The bond with the one central the device pairs with.
//!
//! A [`Bond`] holds the central's identity address with its type, its
//! identity resolving key if it sent one, the long term key, whether the
//! pairing was authenticated, the [`Variant`] of our own identity it was made
//! under, the central's client characteristic configuration bits
//! ([`crate::host::gatt::Subscriptions::bits`]) and, only for a table with the
//! Service Changed characteristic, part of the table's layout hash.
//!
//! A table without the Service Changed characteristic makes bonds that keep
//! no layout: [`Bond::new`] takes it from the table, and
//! [`Bond::layout_known`] holds for such a table whatever the bond keeps.
//!
//! The firmware stores a bond in flash as [`BOND_LEN`] octets
//! ([`Bond::to_bytes`] and [`Bond::from_bytes`]); this module knows nothing
//! about flash. The first octet is a version, [`BOND_VERSION`], so erased
//! flash (all ones), zeros and records of another version are refused, as is
//! a record whose fields contradict each other. The record has no checksum:
//! the firmware's storage is to detect torn writes itself. The layout:
//!
//! | Octets | Field |
//! |---|---|
//! | 0 | Version, [`BOND_VERSION`] |
//! | 1 | Flags: bit 0 the central's identity address is random, bit 1 it sent an identity resolving key, bit 2 the pairing was authenticated, bit 3 a layout is kept; the others zero |
//! | 2 to 7 | The central's identity address, least significant octet first |
//! | 8 to 23 | Its identity resolving key, least significant octet first, or zeros |
//! | 24 to 39 | The long term key, least significant octet first |
//! | 40, 41 | Our [`Variant`], least significant octet first |
//! | 42 to 45 | The client characteristic configuration bits, least significant octet first |
//! | 46 to 49 | The layout, the first four octets of the table's hash, or zeros |
//!
//! Keys are kept least significant octet first, the order the security
//! manager's PDUs carry them in and [`crate::link::Link::ltk_reply`] and
//! [`crate::link::Link::add_peer`] take them in. A bond overwrites its keys
//! when it is dropped; the octets of [`Bond::to_bytes`] hold them too and are
//! the caller's to wipe.

use crate::{
    bytes::{le16, le16_bytes, le32, le32_bytes},
    crypto::wipe,
    host::{
        gatt::{Db, Subscriptions},
        identity::Variant,
    },
    pdu::Peer,
};

/// Octets of a stored bond.
pub const BOND_LEN: usize = 50;
/// The version of the stored form, its first octet.
pub const BOND_VERSION: u8 = 1;

/// Flag: the central's identity address is random.
const FLAG_RANDOM: u8 = 0x01;
/// Flag: the central sent an identity resolving key.
const FLAG_IRK: u8 = 0x02;
/// Flag: the pairing was authenticated.
const FLAG_AUTHENTICATED: u8 = 0x04;
/// Flag: a layout is kept.
const FLAG_LAYOUT: u8 = 0x08;
/// Every flag.
const FLAGS: u8 = FLAG_RANDOM | FLAG_IRK | FLAG_AUTHENTICATED | FLAG_LAYOUT;

/// The bond with the central: see the module documentation. Its keys are
/// overwritten when it is dropped.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Bond {
    /// Whether the pairing was authenticated, with protection against a man
    /// in the middle. Just Works pairing is not.
    pub authenticated: bool,
    /// The client characteristic configuration bits, two for each
    /// descriptor, as [`Subscriptions::bits`] gives them.
    pub cccd:          u32,
    /// The first four octets of the table's layout hash, least significant
    /// octet first, as the central last learned the table; only for a table
    /// with the Service Changed characteristic.
    pub layout:        Option<u32>,
    /// Our identity's variant at the pairing.
    pub local:         Variant,
    /// The long term key, least significant octet first.
    pub ltk:           [u8; 16],
    /// The central's identity address and its type.
    pub peer:          Peer,
    /// The central's identity resolving key, least significant octet first,
    /// if it sent one. `BlueZ` sends one only with host privacy on.
    pub peer_irk:      Option<[u8; 16]>,
}

impl Bond {
    /// The bond as stored, `bytes`, or `None` for another version, erased
    /// flash or a record whose fields contradict each other: an unknown
    /// flag, a key or layout given without its flag, an identity resolving
    /// key flagged but zero, a zero long term key or address, or a random
    /// identity address that is not static.
    #[inline]
    #[must_use = "the bond is only decoded"]
    pub fn from_bytes(bytes: &[u8; BOND_LEN]) -> Option<Self> {
        let (&[version, flags], after_flags) = bytes.split_first_chunk::<2>()?;
        let (&address, after_address) = after_flags.split_first_chunk::<6>()?;
        let (&irk_octets, after_irk) = after_address.split_first_chunk::<16>()?;
        let (&ltk, after_ltk) = after_irk.split_first_chunk::<16>()?;
        let (&local, after_local) = after_ltk.split_first_chunk::<2>()?;
        let (&cccd, after_cccd) = after_local.split_first_chunk::<4>()?;
        let &layout_octets = after_cccd.first_chunk::<4>()?;
        if version != BOND_VERSION || flags & !FLAGS != 0 {
            return None;
        }
        let peer = Peer::new(address, flags & FLAG_RANDOM != 0);
        let peer_irk = match (flags & FLAG_IRK != 0, irk_octets == [0; 16]) {
            (true, false) => Some(irk_octets),
            (false, true) => None,
            _ => return None,
        };
        // A layout may be zero; without one the octets must be.
        let layout = match (flags & FLAG_LAYOUT != 0, layout_octets == [0; 4]) {
            (true, _) => Some(le32(layout_octets)),
            (false, true) => None,
            (false, false) => return None,
        };
        if ltk == [0; 16] || !is_identity(peer) {
            return None;
        }
        Some(Self {
            authenticated: flags & FLAG_AUTHENTICATED != 0,
            cccd: le32(cccd),
            layout,
            local: Variant::from_bits(le16(local)),
            ltk,
            peer,
            peer_irk,
        })
    }

    /// Whether the central knows the table's current layout: always for a
    /// table without the Service Changed characteristic, which keeps none.
    /// Otherwise the host is to indicate Service Changed.
    #[inline]
    #[must_use = "the comparison is only computed"]
    pub fn layout_known(&self, db: &Db) -> bool { layout(db).is_none_or(|current| self.layout == Some(current)) }

    /// A bond from an unauthenticated pairing, with no subscriptions yet,
    /// keeping `db`'s layout if it has the Service Changed characteristic.
    #[inline]
    #[must_use = "the bond is only built"]
    pub fn new(peer: Peer, peer_irk: Option<[u8; 16]>, ltk: [u8; 16], local: Variant, db: &Db) -> Self {
        Self { authenticated: false, cccd: 0, layout: layout(db), local, ltk, peer, peer_irk }
    }

    /// Records whether the pairing was authenticated.
    #[cfg(feature = "passkey")]
    pub(crate) const fn set_authenticated(&mut self, authenticated: bool) { self.authenticated = authenticated; }

    /// The bond's subscriptions to restore on `db`: bits past `db`'s
    /// descriptors, which a bond of an older table may hold, are left out.
    #[inline]
    #[must_use = "the subscriptions are only built"]
    pub fn subscriptions(&self, db: &Db) -> Subscriptions {
        let bits = u32::from(db.cccds()).saturating_mul(2);
        let mask = u32::checked_shl(1, bits).map_or(u32::MAX, |bit| bit.wrapping_sub(1));
        Subscriptions::from_bits(self.cccd & mask)
    }

    /// The bond as stored: see the module documentation. The octets hold
    /// the keys and are the caller's to wipe.
    #[inline]
    #[must_use = "the octets are only built"]
    pub fn to_bytes(&self) -> [u8; BOND_LEN] {
        let mut flags = 0;
        for (set, flag) in [
            (self.peer.random, FLAG_RANDOM),
            (self.peer_irk.is_some(), FLAG_IRK),
            (self.authenticated, FLAG_AUTHENTICATED),
            (self.layout.is_some(), FLAG_LAYOUT),
        ] {
            if set {
                flags |= flag;
            }
        }
        let mut bytes = [0; BOND_LEN];
        let mut rest = bytes.as_mut_slice();
        for field in [
            &[BOND_VERSION, flags][..],
            &self.peer.address,
            &self.peer_irk.unwrap_or_default(),
            &self.ltk,
            &le16_bytes(self.local.bits()),
            &le32_bytes(self.cccd),
            &le32_bytes(self.layout.unwrap_or_default()),
        ] {
            let (target, tail) = rest.split_at_mut(field.len().min(rest.len()));
            target.copy_from_slice(field.get(..target.len()).unwrap_or_default());
            rest = tail;
        }
        bytes
    }
}

impl Drop for Bond {
    #[inline]
    fn drop(&mut self) {
        wipe(&mut self.ltk);
        if let Some(irk) = self.peer_irk.as_mut() {
            wipe(irk);
        }
    }
}

/// Whether `peer` can be an identity address: a public address, or a static
/// random one (two most significant bits set), and not zero.
fn is_identity(peer: Peer) -> bool {
    peer.address != [0; 6] && (!peer.random || peer.address.last().is_some_and(|&top| top & 0xC0 == 0xC0))
}

/// The layout a bond with `db` keeps: the first four octets of its hash,
/// least significant octet first, for a table with the Service Changed
/// characteristic.
fn layout(db: &Db) -> Option<u32> {
    db.service_changed().map(|_| le32(db.hash().first_chunk::<4>().copied().unwrap_or_default()))
}

#[cfg(test)] mod tests;
