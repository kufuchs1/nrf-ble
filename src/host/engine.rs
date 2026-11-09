//! The protocol engine: all of the host's protocol state, without futures and
//! without input or output of its own.
//!
//! The engine takes the link layer's events and received fragments, the time
//! and the results of the P-256 jobs, and gives the next fragment to send, the
//! next deadline, the next job and the events for the application. The async
//! glue around it waits for the link layer, the next deadline, and the
//! return of room to send, whichever comes first.
//!
//! Notifications are paced by acknowledgement: at most one is unacknowledged
//! at a time, counted with the link layer's acknowledged fragments, and one
//! link layer buffer is always kept for ATT responses, signalling and the
//! security manager.
