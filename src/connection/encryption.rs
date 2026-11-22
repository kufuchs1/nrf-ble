//! Link encryption: the state of the encryption and of its start and pause
//! procedures (Core, Vol 6, Part B, 5.1.3 and 5.1.4). The steps of the
//! procedures stay with the connection, whose methods live in one file.

use crate::crypto::{self, CONFIG_LEN, SCRATCH_LEN};

/// The central's encryption request as the host looks up the key by it.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
pub(super) struct KeyLookup {
    /// Central encrypted diversifier.
    pub ediv: [u8; 2],
    /// Central random number.
    pub rand: [u8; 8],
}

/// State of the link encryption and its start and pause procedures. The
/// phase alone says in which directions packets are encrypted, so the two
/// directions cannot disagree with the procedure.
///
/// The discriminants only keep the checks within the interframe space short.
/// The phases that receive encrypted are 0 to 2, so [`Self::rx_on`] is one
/// compare. Those that send encrypted are 1 to 3, and the two idle phases
/// differ in one bit.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
#[repr(u8)]
pub(super) enum Phase {
    /// A validated request waits for its prefetched, single-use random block.
    AwaitingEntropy(KeyLookup) = 7,
    /// The host is asked for the long term key, and whether the key request
    /// event reached it yet.
    AwaitingKey(KeyLookup, bool) = 8,
    /// Our encrypted pause response was sent; the central's plain one is
    /// expected.
    AwaitingPauseResponse = 3,
    /// The start request was sent and the peer must authenticate its reply.
    AwaitingStartResponse = 0,
    /// No procedure running, and the link is encrypted both ways.
    Encrypted       = 2,
    /// Encryption is paused both ways; the central starts it again with the
    /// new key.
    Paused          = 5,
    /// Our pause response is queued, still encrypted.
    Pausing         = 1,
    /// No procedure running, and the link is not encrypted: it never was,
    /// or the host had no key for its first start.
    Plain           = 6,
    /// Encryption is being started.
    Starting        = 4,
}

impl Phase {
    /// Whether a PDU queued now goes out as the central reads it: no
    /// procedure runs, or one that has not yet queued the PDU after which the
    /// central reads ours differently, our `LL_START_ENC_REQ` or
    /// `LL_PAUSE_ENC_RSP`. Behind either a PDU would go out plain to a
    /// central that decrypts it, or encrypted to one that no longer does.
    pub(super) const fn consistent(self) -> bool {
        matches!(self, Self::AwaitingEntropy(_) | Self::AwaitingKey(..) | Self::Encrypted | Self::Paused | Self::Plain)
    }

    /// Whether no encryption procedure runs.
    pub(super) const fn is_idle(self) -> bool { matches!(self, Self::Encrypted | Self::Plain) }

    /// Whether received packets are encrypted: once our start request was
    /// sent, until our pause response was sent.
    pub(super) const fn rx_on(self) -> bool {
        matches!(self, Self::AwaitingStartResponse | Self::Encrypted | Self::Pausing)
    }

    /// Whether sent packets are encrypted, from the next PDU prepared: from
    /// the central's start response on, until its pause response.
    pub(super) const fn tx_on(self) -> bool {
        matches!(self, Self::AwaitingPauseResponse | Self::Encrypted | Self::Pausing)
    }
}

/// Kind of encryption start.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Procedure {
    /// The first start of the connection.
    First,
    /// A key refresh after a pause.
    Refresh,
}

/// Link encryption state.
pub(super) struct Encryption {
    /// Whether the decryption of the packet under way was started on its
    /// access address ([`crypto::start_on_address`]).
    pub armed:      bool,
    /// IV of the session.
    pub iv:         [u8; 8],
    /// State of the encryption and its procedures.
    pub phase:      Phase,
    /// Whether the start is the first or refreshes the key.
    pub procedure:  Procedure,
    /// CCM configuration for received packets.
    pub rx_config:  [u8; CONFIG_LEN],
    /// Packet counter of the next new received packet.
    pub rx_counter: u64,
    /// CCM scratch area.
    pub scratch:    [u8; SCRATCH_LEN],
    /// Session key diversifier.
    pub skd:        [u8; 16],
    /// CCM configuration for sent packets.
    pub tx_config:  [u8; CONFIG_LEN],
    /// Packet counter of the next new sent packet.
    pub tx_counter: u64,
}

impl Encryption {
    /// Forgets the keys, the IVs and the session key diversifier of the
    /// link.
    pub(super) fn wipe(&mut self) {
        crypto::wipe(&mut self.iv);
        crypto::wipe(&mut self.rx_config);
        crypto::wipe(&mut self.scratch);
        crypto::wipe(&mut self.skd);
        crypto::wipe(&mut self.tx_config);
    }
}
