//! The cryptographic functions of the security manager: AES-CMAC and the
//! functions f4, f5, f6, g2 and ah of the Core specification, volume 3, part
//! H, section 2.2.
//!
//! They are written from the specification and tested against its sample
//! data. Every AES block goes through the [`crate::host::Aes`] trait: the
//! hardware ECB in the firmware, software AES in the host tests.
