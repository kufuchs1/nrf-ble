//! The typed interface between the link layer and the host.
//!
//! The host in [`crate::host`] talks to the link layer through this module
//! only, with Rust types and no serialised HCI: no command or event is
//! encoded into bytes and parsed again. It replaces the byte level
//! [`crate::hci`] module, which goes once this module is complete.
//!
//! What it provides, as the next stage fills it:
//!
//! - `Link`, a copyable handle on the link layer's shared state, and `Epoch`,
//!   which names one connection: a request for a link that has ended carries an
//!   old epoch and has no effect on the next link.
//! - Identity, resolving list and advertising set up from typed parameters.
//! - `Link::next`, the link layer's events and received ACL fragments in the
//!   order they happened. The event queue holds 6 events, as the thread
//!   executor stalls for about 3 s during a P-256 multiplication.
//! - `AclIn`, a received fragment with an `encrypted` flag set when the PDU was
//!   received on the air, so the host's security checks do not depend on the
//!   order in which it learns of the encryption.
//! - Sending with `try_send`, the free room with `tx_room`, a wake-up when room
//!   returns (`tx_room_changed`), and the count of acknowledged fragments, so
//!   the host can keep at most one notification unacknowledged.
//! - The peripheral latency hold: no connection event is skipped for about 200
//!   ms or 8 events after a non-empty PDU in either direction and during the
//!   first second of a link, and `hold_latency(bool)` keeps every event while
//!   the host asks for it.
