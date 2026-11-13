//! Integers to and from octets in a given byte order.
//!
//! The standard `{to,from}_{le,be}_bytes`, which the lints refuse, are the
//! integer's octets in memory, turned around where the CPU's byte order is
//! the other one; so are these, with `{to,from}_{le,be}` for the turn. Built
//! from shifts and truncation instead, a value cut from a wider integer is
//! stored octet by octet at `opt-level = 3`, which made the connection event
//! larger.
//!
//! The link layer and the host's PDUs are least significant octet first
//! (Core, Vol 6, Part B, 1.2), the security manager's functions (AES-CMAC,
//! f4, f5, f6, g2, P-256) most significant octet first (Core, Vol 3, Part H,
//! 2.2). Nothing here depends on the byte order of the CPU.

use core::ptr;

/// The integer whose octets in memory are `bytes`.
macro_rules! from_memory {
    ($bytes:ident as $int:ty) => {
        // SAFETY: the array has the integer's size, every bit pattern is an
        // integer, and the read needs no alignment.
        unsafe { ptr::read_unaligned(ptr::from_ref(&$bytes).cast::<$int>()) }
    };
}

/// The octets of `value` in memory.
macro_rules! to_memory {
    ($value:expr => $len:literal) => {{
        let mut bytes = [0; $len];
        // SAFETY: the array has the integer's size, and the write needs no
        // alignment.
        unsafe { ptr::write_unaligned(ptr::from_mut(&mut bytes).cast(), $value) };
        bytes
    }};
}

/// A `u16` from two octets, least significant first.
#[inline]
#[must_use = "the value is only computed"]
pub const fn le16(bytes: [u8; 2]) -> u16 { u16::from_le(from_memory!(bytes as u16)) }

/// The two octets of `value`, least significant first.
#[inline]
#[must_use = "the octets are only computed"]
pub const fn le16_bytes(value: u16) -> [u8; 2] { to_memory!(value.to_le() => 2) }

/// A `u32` from four octets, least significant first.
#[inline]
#[must_use = "the value is only computed"]
pub const fn le32(bytes: [u8; 4]) -> u32 { u32::from_le(from_memory!(bytes as u32)) }

/// The four octets of `value`, least significant first.
#[inline]
#[must_use = "the octets are only computed"]
pub const fn le32_bytes(value: u32) -> [u8; 4] { to_memory!(value.to_le() => 4) }

/// The eight octets of `value`, least significant first.
#[inline]
#[must_use = "the octets are only computed"]
pub const fn le64_bytes(value: u64) -> [u8; 8] { to_memory!(value.to_le() => 8) }

/// The two octets of `value`, most significant first.
#[inline]
#[must_use = "the octets are only computed"]
pub const fn be16_bytes(value: u16) -> [u8; 2] { to_memory!(value.to_be() => 2) }

/// A `u32` from four octets, most significant first.
#[inline]
#[must_use = "the value is only computed"]
pub const fn be32(bytes: [u8; 4]) -> u32 { u32::from_be(from_memory!(bytes as u32)) }

/// The four octets of `value`, most significant first.
#[cfg(any(test, feature = "passkey"))]
#[inline]
#[must_use = "the octets are only computed"]
pub const fn be32_bytes(value: u32) -> [u8; 4] { to_memory!(value.to_be() => 4) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_the_standard_conversions() {
        for value in [0, 1, 0x00FF, 0x0100, 0x1234, 0xFF00, u16::MAX] {
            assert_eq!(le16_bytes(value), value.to_le_bytes());
            assert_eq!(be16_bytes(value), value.to_be_bytes());
            assert_eq!(le16(value.to_le_bytes()), value);
        }
        for value in [0, 1, 0x1234_5678, 0x8000_0001, u32::MAX] {
            assert_eq!(le32_bytes(value), value.to_le_bytes());
            assert_eq!(be32_bytes(value), value.to_be_bytes());
            assert_eq!(le32(value.to_le_bytes()), value);
            assert_eq!(be32(value.to_be_bytes()), value);
        }
        for value in [0, 1, 0x0123_4567_89AB_CDEF, u64::MAX] {
            assert_eq!(le64_bytes(value), value.to_le_bytes());
        }
    }
}
