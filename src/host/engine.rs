//! The protocol engine: all of the host's protocol state, without futures and
//! without input or output of its own.
//!
//! Not written yet: the engine stage fills this module. What it is to do:
//!
//! - Take the link layer's events and received fragments, the time and the
//!   results of the P-256 jobs. Give the next fragment to send, the next
//!   deadline, the next job and the events for the application.
//! - Have its async glue wait for whichever comes first: the link layer
//!   ([`crate::link::Link::next`]), the next deadline, or the return of room to
//!   send ([`crate::link::Link::tx_room_changed`]).
//! - Pace notifications by acknowledgement: at most one unacknowledged at a
//!   time, counted with [`crate::link::Link::in_flight`], not by waiting until
//!   everything is flushed. One link layer buffer is always kept for ATT
//!   responses, signalling and the security manager.
//! - Hold the peripheral latency off with [`crate::link::Link::hold_latency`]
//!   from the connection until discovery and the input reports' configuration
//!   are done and ATT has been idle for a while.
//! - Restore the bond's client characteristic configuration
//!   ([`crate::host::att::Server::restore`]) only once the link is encrypted
//!   with the bond's key, never at the connection: nothing is notified before
//!   the encryption, which also keeps the link layer buffers free for the
//!   pairing's burst.
//! - Give the ATT server, for each request, the security of the link as the
//!   request was received ([`crate::link::AclIn::encrypted`] and the key the
//!   host handed over with [`crate::link::Link::ltk_reply`]), and wipe the
//!   Diffie-Hellman key, the `MacKey` and the long term key once they are no
//!   longer needed ([`crate::host::smp::ecc`] and [`crate::host::smp::toolbox`]
//!   wipe their own).
