//! The attribute protocol, as a server with the default MTU of 23 octets.
//!
//! Not written yet: the ATT stage fills this module. What it is to do:
//!
//! - Decode the requests BlueZ sends, answer them from the GATT table with the
//!   error codes of the Core specification, and encode notifications and
//!   indications. One request is outstanding at a time, and one indication
//!   waits for its confirmation for at most 30 s.
//! - Serve an attribute that needs an encrypted link only for a request that
//!   was itself received encrypted ([`crate::link::AclIn::encrypted`]), on a
//!   link whose key the host handed to the link layer itself, with
//!   [`crate::link::Link::ltk_reply`]. The check never depends on the order in
//!   which the host learns of the encryption.
//! - Be tested with golden PDUs for the whole BlueZ first connection sequence
//!   (design, section 6, item 4).
