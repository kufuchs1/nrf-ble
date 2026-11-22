//! The bond with the one central the device pairs with.
//!
//! A [`Bond`] holds the central's identity address with its type, its
//! identity resolving key if it sent one, the long term key, whether the
//! pairing was authenticated, the [`Variant`] of our own identity it was made
//! under, the central's client characteristic configuration bits
//! ([`crate::host::gatt::Subscriptions::bits`]), the Client Supported Features
//! bits it wrote ([`Bond::client_features`]), whether directed advertising
//! reaches the central ([`Bond::directed_works`]) and, only for a table with
//! the Service Changed characteristic, part of the table's layout hash.
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
//! | 1 | Flags: bit 0 the central's identity address is random, bit 1 it sent an identity resolving key, bit 2 the pairing was authenticated, bit 3 a layout is kept, bit 4 directed advertising went unanswered ([`Bond::directed_works`] false), bits 5 to 7 the central's Client Supported Features bits 0 to 2 ([`Bond::client_features`]) |
//! | 2 to 7 | The central's identity address, least significant octet first |
//! | 8 to 23 | Its identity resolving key, least significant octet first, or zeros |
//! | 24 to 39 | The long term key, least significant octet first |
//! | 40, 41 | Our [`Variant`], least significant octet first |
//! | 42 to 45 | The client characteristic configuration bits, least significant octet first |
//! | 46 to 49 | The layout, the first four octets of the table's hash, or zeros |
//!
//! Bit 4 clear reads as directed advertising working, and bits 5 to 7 clear
//! as a central that wrote no Client Supported Features bit: both the state
//! of a new bond. Every bit of the flags octet has a meaning: a further flag
//! needs another version, [`BOND_VERSION`] 2, or another octet.
//!
//! Keys are kept least significant octet first, the order the security
//! manager's PDUs carry them in and [`crate::link::Link::ltk_reply`] and
//! [`crate::link::Link::add_peer`] take them in. A bond overwrites its keys
//! when it is dropped; the octets of [`Bond::to_bytes`] hold them too and are
//! the caller's to wipe.

use crate::{
    crypto::wipe,
    host::{
        gatt::{Db, Subscriptions},
        identity::Variant,
    },
    pdu::{IdentityAddress, Peer, concat_into},
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
/// Flag: directed advertising went unanswered, [`Bond::directed_works`] is
/// false.
const FLAG_UNDIRECTED: u8 = 0x10;
/// The flags bit of bit 0 of [`Bond::client_features`]: flags bits 5 to 7
/// hold its bits 0 to 2.
const CLIENT_FEATURES_SHIFT: u32 = 5;
/// The Client Supported Features bits a bond keeps, bits 0 to 2: the ones the
/// specification defines (Core, Vol 3, Part G, 7.2, Table 7.6).
const CLIENT_FEATURES: u8 = 0x07;

/// The bond with the central: see the module documentation. Its keys are
/// overwritten when it is dropped.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Bond {
    /// Whether the pairing was authenticated, with protection against a man
    /// in the middle. Just Works pairing is not.
    pub authenticated:   bool,
    /// The client characteristic configuration bits, two for each
    /// descriptor, as [`Subscriptions::bits`] gives them.
    pub cccd:            u32,
    /// The Client Supported Features bits the central wrote (Core, Vol 3,
    /// Part G, 7.2): bit 0 Robust Caching, bit 1 Enhanced ATT bearers, bit 2
    /// Multiple Handle Value Notifications. Zero for a new bond. The stored
    /// form keeps bits 0 to 2, the ones the specification defines; the others
    /// are not stored and read back as zero.
    pub client_features: u8,
    /// Whether a reconnection may start with directed advertising
    /// (`host::adv::Mode::directs`, feature `directed-advertising`): true for
    /// a new bond, false once a directed phase went unanswered and the
    /// central then connected, with this bond's key, to the undirected
    /// advertising right after it ([`crate::link::Info::directed`] false). Such
    /// a central does not resolve the resolvable private address directed
    /// advertising targets, or is not listening for it, so the directed phase
    /// only delays it; the host clears this and reports the bond to store
    /// ([`crate::host::ConnEvent::BondUpdated`]), and only a new pairing, or
    /// the firmware itself, sets it again.
    pub directed_works:  bool,
    /// The first four octets of the table's layout hash, least significant
    /// octet first, as the central last learned the table; only for a table
    /// with the Service Changed characteristic.
    pub layout:          Option<u32>,
    /// Our identity's variant at the pairing.
    pub local:           Variant,
    /// The long term key, least significant octet first.
    pub ltk:             [u8; 16],
    /// The central's identity address and its type.
    pub peer:            IdentityAddress,
    /// The central's identity resolving key, least significant octet first,
    /// if it sent one. `BlueZ` sends one only with host privacy on.
    pub peer_irk:        Option<[u8; 16]>,
}

impl Bond {
    /// The bond as stored, `bytes`, or `None` for another version, erased
    /// flash or a record whose fields contradict each other: a key or layout
    /// given without its flag, an identity resolving key flagged but zero, a
    /// zero long term key, or an address that is no [`IdentityAddress`].
    /// Every bit of the flags octet has a meaning, so the flags alone never
    /// refuse a record.
    #[inline]
    #[must_use = "the bond is only decoded"]
    pub const fn from_bytes(bytes: &[u8; BOND_LEN]) -> Option<Self> {
        let (&[version, flags], after_flags) = bytes.split_first_chunk::<2>()?;
        let (&address, after_address) = after_flags.split_first_chunk::<6>()?;
        let (&irk_octets, after_irk) = after_address.split_first_chunk::<16>()?;
        let (&ltk, after_ltk) = after_irk.split_first_chunk::<16>()?;
        let (&local, after_local) = after_ltk.split_first_chunk::<2>()?;
        let (&cccd, after_cccd) = after_local.split_first_chunk::<4>()?;
        let &layout_octets = after_cccd.first_chunk::<4>()?;
        if version != BOND_VERSION {
            return None;
        }
        let peer = IdentityAddress::new(Peer::new(address, flags & FLAG_RANDOM != 0))?;
        let peer_irk = match (flags & FLAG_IRK != 0, irk_octets == [0; 16]) {
            (true, false) => Some(irk_octets),
            (false, true) => None,
            _ => return None,
        };
        // A layout may be zero; without one the octets must be.
        let layout = match (flags & FLAG_LAYOUT != 0, layout_octets == [0; 4]) {
            (true, _) => Some(u32::from_le_bytes(layout_octets)),
            (false, true) => None,
            (false, false) => return None,
        };
        if ltk == [0; 16] {
            return None;
        }
        Some(Self {
            authenticated: flags & FLAG_AUTHENTICATED != 0,
            cccd: u32::from_le_bytes(cccd),
            client_features: flags.unbounded_shr(CLIENT_FEATURES_SHIFT),
            directed_works: flags & FLAG_UNDIRECTED == 0,
            layout,
            local: Variant::from_bits(u16::from_le_bytes(local)),
            ltk,
            peer,
            peer_irk,
        })
    }

    /// Whether the central knows the table's current layout: always for a
    /// table without the Service Changed characteristic, which keeps none.
    /// Otherwise the central would need the Service Changed indication,
    /// which the host does not send.
    #[inline]
    #[must_use = "the comparison is only computed"]
    pub fn layout_known(&self, db: &Db) -> bool { layout(db).is_none_or(|current| self.layout == Some(current)) }

    /// A bond from an unauthenticated pairing, with no subscriptions and no
    /// Client Supported Features bits yet, keeping `db`'s layout if it has the
    /// Service Changed characteristic.
    #[inline]
    #[must_use = "the bond is only built"]
    pub fn new(peer: IdentityAddress, peer_irk: Option<[u8; 16]>, ltk: [u8; 16], local: Variant, db: &Db) -> Self {
        Self {
            authenticated: false,
            cccd: 0,
            client_features: 0,
            directed_works: true,
            layout: layout(db),
            local,
            ltk,
            peer,
            peer_irk,
        }
    }

    /// Records whether the pairing was authenticated.
    #[cfg(feature = "passkey")]
    pub(crate) const fn set_authenticated(&mut self, authenticated: bool) { self.authenticated = authenticated; }

    /// The bond's subscriptions to restore on `db`: bits past `db`'s
    /// descriptors, which a bond of an older table may hold, are left out.
    #[inline]
    #[must_use = "the subscriptions are only built"]
    pub const fn subscriptions(&self, db: &Db) -> Subscriptions {
        let bits = u32::from(db.cccds()).saturating_mul(2);
        let mask = 1_u32.unbounded_shl(bits).wrapping_sub(1);
        Subscriptions::from_bits(self.cccd & mask)
    }

    /// The bond as stored: see the module documentation. The octets hold
    /// the keys and are the caller's to wipe.
    #[inline]
    #[must_use = "the octets are only built"]
    pub fn to_bytes(&self) -> [u8; BOND_LEN] {
        let mut flags = (self.client_features & CLIENT_FEATURES).unbounded_shl(CLIENT_FEATURES_SHIFT);
        for (set, flag) in [
            (self.peer.peer().random, FLAG_RANDOM),
            (self.peer_irk.is_some(), FLAG_IRK),
            (self.authenticated, FLAG_AUTHENTICATED),
            (self.layout.is_some(), FLAG_LAYOUT),
            (!self.directed_works, FLAG_UNDIRECTED),
        ] {
            if set {
                flags |= flag;
            }
        }
        let mut bytes = [0; BOND_LEN];
        concat_into(&mut bytes, &[
            &[BOND_VERSION, flags],
            &self.peer.peer().address,
            &self.peer_irk.unwrap_or_default(),
            &self.ltk,
            &self.local.bits().to_le_bytes(),
            &self.cccd.to_le_bytes(),
            &self.layout.unwrap_or_default().to_le_bytes(),
        ]);
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

/// The layout a bond with `db` keeps: the first four octets of its hash,
/// least significant octet first, for a table with the Service Changed
/// characteristic.
fn layout(db: &Db) -> Option<u32> {
    db.service_changed().map(|_| {
        let [hash0, hash1, hash2, hash3, ..] = db.hash();
        u32::from_le_bytes([hash0, hash1, hash2, hash3])
    })
}

#[cfg(test)] mod tests;
