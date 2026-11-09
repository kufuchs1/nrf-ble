//! The device's own identity: a static random address and an identity
//! resolving key.
//!
//! Not written yet: the advertising stage fills this module. What it is to
//! do: derive both from the chip's encryption and identity root in FICR and a
//! variant number, with AES, so the firmware can change identity without
//! storing it. The address has its two most significant bits set, as a static
//! random address must.
