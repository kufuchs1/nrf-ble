//! The GATT server's attribute table.
//!
//! The table is a constant array in flash, with the handle of each attribute
//! one more than its index. Values are constant bytes, zeros of a given
//! length, a write sink, dynamic values the application reads and writes, or
//! client characteristic configuration bits, which the host keeps for the
//! link and restores from the bond.
//!
//! The table builder makes the Service Changed characteristic optional: the
//! Spotlight table has none. Where it is present, an indication goes out only
//! after the central wrote its client characteristic configuration on that
//! link. Read By Group Type reports the real end handle of the last service,
//! never 0xFFFF. The Peripheral Preferred Connection Parameters come from the
//! same parameter range as the host's connection parameter request.

/// The constant hash of the table's layout.
pub mod hash;
