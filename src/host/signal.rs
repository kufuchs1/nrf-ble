//! The LE signalling channel (CID 5).
//!
//! Not written yet: the ATT stage fills this module. What it is to do:
//!
//! - Send the Connection Parameter Update Request and take its response. The
//!   request asks for the same [`crate::link::ParamRange`] as the Peripheral
//!   Preferred Connection Parameters characteristic, so BlueZ never finds the
//!   two disagreeing.
//! - Answer a request it does not serve with a Command Reject (Core, Vol 3,
//!   Part A, 4.1): reason 0x0000 without data, or for a request on a channel
//!   that does not exist, reason 0x0002 with the four octets of the local and
//!   remote CID.
//! - Never answer a response or a Command Reject. A Command Reject with the
//!   identifier of our request rejects it; any other response, and any command
//!   with identifier 0 or a length field that does not match, is dropped, as
//!   Linux drops them.
