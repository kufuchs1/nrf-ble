//! The LE signalling channel (CID 5).
//!
//! The host sends the Connection Parameter Update Request and takes its
//! response, and answers every other command with a Command Reject. The
//! request asks for the same parameter range as the Peripheral Preferred
//! Connection Parameters characteristic in the GATT table: both come from one
//! parameter range, so BlueZ never finds the two disagreeing.
