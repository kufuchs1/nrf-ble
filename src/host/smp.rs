//! The security manager: LE Secure Connections pairing as responder.
//!
//! Not written yet: the security manager stage fills this module. What it is
//! to do:
//!
//! - Pair with Just Works, bond, and distribute the identity resolving key and
//!   identity address, taking the central's in return. A pairing that does not
//!   complete within 30 s fails. Requests without Secure Connections, with a
//!   key size under 16 octets, or while a bond is set and pairing is not
//!   allowed, are refused.
//! - Use the addresses on the air for f5 and f6: the central's and ours from
//!   [`crate::link::Info`], with their types, not the identities.
//! - Hand the long term key to [`crate::link::Link::ltk_reply`] least
//!   significant octet first: f5 gives it most significant octet first, so it
//!   is reversed, and tested with the f5 sample data through the link layer's
//!   session key derivation.
//! - Run the P-256 key generation and Diffie-Hellman as jobs outside the state
//!   machine, on their own task, as each blocks the thread for about 3 s on the
//!   nRF51. The application's watchdog hook is called right before each
//!   multiplication, and the task yields between two jobs.

/// The P-256 scalar multiplication.
pub mod ecc;
/// The cryptographic functions of pairing.
pub mod toolbox;
