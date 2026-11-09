//! The L2CAP fixed channels of a low energy link.
//!
//! Not written yet: the ATT stage fills this module. What it is to do:
//!
//! - Join received fragments into one PDU in a single 72 octet buffer, the size
//!   of the largest PDU the host takes (an SMP Public Key, 4 + 65 octets). A
//!   start fragment begins a new PDU; a continuation without a start, or a PDU
//!   longer than the buffer, is dropped.
//! - Pass the PDU to its channel by CID: 4 (ATT), 5 (LE signalling) or 6
//!   (security manager); any other CID is dropped.
//! - Render outgoing PDUs fragment by fragment into link layer payloads of up
//!   to 27 octets as the link has room, so no transmit buffer holds a whole
//!   PDU, and the fragments of two PDUs never interleave.
