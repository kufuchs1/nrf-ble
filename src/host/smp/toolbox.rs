//! The cryptographic functions of the security manager: AES-CMAC and the
//! functions f4, f5, f6, g2 and ah of the Core specification, volume 3, part
//! H, section 2.2.
//!
//! Not written yet: the security manager stage fills this module. They are
//! to be written from the specification, most significant octet first, and
//! tested against RFC 4493 and the specification's sample data. Every AES
//! block goes through the [`crate::host::Aes`] trait: the hardware ECB in the
//! firmware, software AES in the host tests.
