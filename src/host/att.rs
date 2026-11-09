//! The attribute protocol, as a server with the default MTU of 23 octets.
//!
//! It decodes the requests BlueZ sends, answers them from the GATT table and
//! encodes notifications and indications, with the error codes of the Core
//! specification. One request is outstanding at a time, and one indication
//! waits for its confirmation for at most 30 s.
//!
//! An attribute that needs an encrypted link is served only for a request
//! that was itself received encrypted, with a key the host handed to the link
//! layer: the check uses the `encrypted` flag the link layer sets on each
//! received fragment, never the order in which the host learnt of the
//! encryption.
