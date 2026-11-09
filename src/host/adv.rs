//! Connectable advertising and the advertising data writer.
//!
//! Not written yet: the advertising stage fills this module. What it is to
//! do:
//!
//! - Build advertising and scan response data in fixed arrays of 31 octets.
//! - Set the filter and the pairing policy from the bond: with a bond, only the
//!   bonded central may connect, unless pairing is allowed.
//! - Have pairable advertising wait for the P-256 key pair before it calls
//!   [`crate::link::Link::advertise`], so a reconnection never computes one.
//! - Handle a connection that arrives while no advertising call is waiting,
//!   because the call's future was dropped: keep it for the next call, or
//!   disconnect it with reason 0x13. Both are to be tested.
