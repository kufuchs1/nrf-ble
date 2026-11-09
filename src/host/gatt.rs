//! The GATT server's attribute table.
//!
//! Not written yet: the ATT stage fills this module. What it is to do:
//!
//! - Keep the table as a constant array in flash, with the handle of each
//!   attribute one more than its index. Values are constant bytes, zeros of a
//!   given length, a write sink, dynamic values the application reads and
//!   writes, or client characteristic configuration bits, which the host keeps
//!   for the link and restores from the bond.
//! - Make the Service Changed characteristic optional in the table builder: the
//!   Spotlight table has none. Where it is present, an indication goes out only
//!   after the host sent the Write Response to that link's write of the Service
//!   Changed client characteristic configuration, as BlueZ registers its
//!   handler only then.
//! - Report the real end handle of the last service in Read By Group Type,
//!   never 0xFFFF.
//! - Take the Peripheral Preferred Connection Parameters from the same
//!   [`crate::link::ParamRange`] as the host's connection parameter request.

/// The constant hash of the table's layout.
pub mod hash;
