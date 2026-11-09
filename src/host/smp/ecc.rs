//! P-256 for LE Secure Connections: key pair generation, the check of the
//! central's public key and the Diffie-Hellman key.
//!
//! Not written yet: the security manager stage fills this module. What it is
//! to do: use the field and point arithmetic of the `p256` crate with a scalar
//! multiplication loop of its own (radix 16), in pure Rust without tables
//! kept in RAM. The central's public key must lie on the curve and must be
//! neither the host's own key nor the debug key of the specification.

// The multiplication loop comes with the security manager stage.
use p256 as _;
