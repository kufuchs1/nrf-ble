//! The security manager: LE Secure Connections pairing as responder.
//!
//! The host pairs with Just Works, bonds, and distributes its identity
//! resolving key and identity address, taking the central's in return. A
//! pairing that does not complete within 30 s fails. Requests without Secure
//! Connections, with a key size under 16 octets, or while a bond is set and
//! pairing is not allowed, are refused.
//!
//! The P-256 key generation and Diffie-Hellman run as jobs outside the state
//! machine, on their own task, as each blocks the thread for about 3 s on the
//! nRF51. The application's watchdog hook is called right before each P-256
//! multiplication, and the task yields between two jobs.

/// The P-256 scalar multiplication.
pub mod ecc;
/// The cryptographic functions of pairing.
pub mod toolbox;
