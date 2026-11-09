//! Connectable advertising and the advertising data writer.
//!
//! The writer builds advertising and scan response data in fixed arrays of 31
//! octets. Advertising sets the filter and the pairing policy from the bond:
//! with a bond, only the bonded central may connect, unless pairing is
//! allowed.
//!
//! Pairable advertising first waits for the P-256 key pair, so a reconnection
//! never computes one. A connection that arrives while no advertising call is
//! waiting is handled explicitly: it is kept for the next call, or
//! disconnected with reason 0x13.
