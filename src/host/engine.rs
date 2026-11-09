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
//!   host handed over with [`crate::link::Link::ltk_reply`]).
//! - Wipe the copies of the long term key it makes: the
//!   [`crate::host::smp::Bonded`] a pairing ends with is `Copy`, so wipe it
//!   once the [`crate::host::bond::Bond`] is built from it. The
//!   [`crate::host::smp::Responder`] wipes its own Diffie-Hellman key, `MacKey`
//!   and long term key; [`crate::host::smp::ecc`] and
//!   [`crate::host::smp::toolbox`] leave theirs to their callers.
//! - Give the [`crate::host::smp::Responder`] the same
//!   [`crate::host::identity::LocalIdentity`] that [`crate::host::adv`] set up
//!   the link layer with ([`crate::host::smp::Responder::set_identity`]), so
//!   pairing distributes the identity our resolvable private address was made
//!   from. A new pairing advertises under the next generation
//!   ([`crate::host::identity::Variant::next_generation`]).
//! - Build the bond from the pairing's outcome: the central's identity from
//!   [`crate::host::smp::Bonded::identity`], or its address on the air when it
//!   sent none, and our variant. Store it, then replace pairing mode's
//!   resolving list entry, which carries our key under an all zero central
//!   address, by the reconnect mode's entry for the bonded central.
