//! The hash of the attribute table, computed as a constant.
//!
//! The Database Hash characteristic (0x2B2A) carries it. The Core
//! specification defines that hash as an AES-CMAC over each attribute's
//! handle, type and, for declarations, value. This one is our own: two
//! 64-bit FNV-1a lanes, as a `const fn`, so the table needs no AES while it
//! is compiled. `BlueZ` only compares the 16 octets with the ones it cached, so
//! any hash that changes with the table serves.
//!
//! It covers each attribute's handle (its position), kind, properties,
//! security, type and UUID, and the bytes of every constant value, so a
//! changed Report Map changes it too. The hash only spares `BlueZ` the
//! rediscovery of an unchanged table, and it does not protect a cached value:
//! on a mismatch `BlueZ` rediscovers, but keeps its cached HID Report Map, and
//! also keeps a cached service whose start handle, UUID and number of handles
//! are the same. A firmware that changes the Report Map without changing the
//! layout therefore changes the HID service's number of handles too (a filler
//! descriptor whose presence follows a revision), or the central has to pair
//! again.

use super::{Access, Attr, Kind, Sec, Uuid, Value};
use crate::bytes::{le16_bytes, le64_bytes};

/// FNV-1a 64-bit offset basis, the first lane's start.
const OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
/// FNV-1a 64-bit prime.
const PRIME: u64 = 0x0000_0100_0000_01B3;
/// Start of the second lane: the basis XOR `0x5A5A_5A5A_5A5A_5A5A`.
const OFFSET_SECOND: u64 = OFFSET ^ 0x5A5A_5A5A_5A5A_5A5A;

/// Two FNV-1a lanes that take every octet; the second takes each octet
/// with its bits inverted, so the lanes differ.
#[derive(Clone, Copy)]
struct Lanes {
    /// The first lane.
    first:  u64,
    /// The second lane.
    second: u64,
}

impl Lanes {
    /// Takes an access: who may read and write.
    const fn access(self, access: Access) -> Self { self.sec(access.read).sec(access.write) }

    /// Takes `byte`.
    const fn byte(self, byte: u8) -> Self {
        Self {
            first:  (self.first ^ u64::from(byte)).wrapping_mul(PRIME),
            second: (self.second ^ u64::from(!byte)).wrapping_mul(PRIME),
        }
    }

    /// Takes each octet of `bytes`, after their number.
    const fn bytes(self, bytes: &[u8]) -> Self {
        // Saturated: only a value's length, which the table keeps far
        // shorter.
        let mut lanes = self.u16(bytes.len().saturating_cast());
        let mut rest = bytes;
        while let Some((&byte, tail)) = rest.split_first() {
            lanes = lanes.byte(byte);
            rest = tail;
        }
        lanes
    }

    /// The 16 octets of the hash, least significant octet first, as the
    /// Database Hash characteristic carries them.
    const fn finish(self) -> [u8; 16] {
        let [a0, a1, a2, a3, a4, a5, a6, a7] = le64_bytes(self.first);
        let [b0, b1, b2, b3, b4, b5, b6, b7] = le64_bytes(self.second);
        [a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]
    }

    /// Takes a security requirement, or none.
    const fn sec(self, sec: Option<Sec>) -> Self {
        self.byte(match sec {
            None => 0,
            Some(Sec::Open) => 1,
            Some(Sec::Encrypted) => 2,
            Some(Sec::Authenticated) => 3,
        })
    }

    /// Takes `value` least significant octet first.
    const fn u16(self, value: u16) -> Self {
        let [low, high] = le16_bytes(value);
        self.byte(low).byte(high)
    }

    /// Takes a UUID with its length.
    const fn uuid(self, uuid: Uuid) -> Self {
        match uuid {
            Uuid::U16(short) => self.byte(2).u16(short),
            Uuid::U128(long) => self.byte(16).bytes(long),
        }
    }

    /// Takes the kind of a value and its constant bytes. The hash's own
    /// value is left out: it is what is computed.
    const fn value(self, value: Value) -> Self {
        match value {
            Value::Cccd(index) => self.byte(1).byte(index),
            Value::Const(bytes) => self.byte(2).bytes(bytes),
            Value::Dynamic(id) => self.byte(3).byte(id.0),
            Value::Empty => self.byte(4),
            Value::Hash => self.byte(5),
            Value::Sink => self.byte(6),
            Value::Zeros(len) => self.byte(7).byte(len),
        }
    }
}

/// The hash of the table `attrs`: see the module documentation.
#[must_use = "the hash is only computed"]
pub(super) const fn layout(attrs: &[Attr]) -> [u8; 16] {
    let mut lanes = Lanes { first: OFFSET, second: OFFSET_SECOND };
    let mut handle: u16 = 1;
    let mut rest = attrs;
    while let Some((attr, tail)) = rest.split_first() {
        lanes = lanes.u16(handle).uuid(attr.uuid);
        lanes = match attr.kind {
            Kind::Characteristic(props) => lanes.byte(1).byte(props),
            Kind::Descriptor(access) => lanes.byte(2).access(access),
            Kind::Service => lanes.byte(3),
            Kind::Value(access, sec) => lanes.byte(4).access(access).sec(Some(sec)),
        };
        lanes = lanes.value(attr.value);
        handle = handle.wrapping_add(1);
        rest = tail;
    }
    lanes.finish()
}
