//! The L2CAP fixed channels of a low energy link.
//!
//! [`Reassembly`] joins received fragments into one PDU in a single buffer of
//! [`RX_MAX`] (72) octets, the size of the largest PDU the host takes: an SMP
//! Pairing Public Key is 4 + 65 octets. A start fragment begins a new PDU and
//! drops an incomplete one. A continuation without a start, a PDU longer than
//! the buffer and a PDU with more octets than its header announces are
//! dropped. A complete PDU goes to its channel by CID: 4 (ATT), 5 (LE
//! signalling) or 6 (security manager); any other CID is dropped. The PDU is
//! encrypted only if each of its fragments was received encrypted.
//!
//! [`Segmenter`] renders an outgoing PDU fragment by fragment into link layer
//! payloads of up to [`FRAGMENT_MAX`] (27) octets, from the PDU's payload as
//! its owner renders it again for each fragment, so no transmit buffer holds
//! a whole PDU. A fragment is taken from it only once the link layer queued
//! it, and the engine starts no other PDU while one is part sent
//! ([`Segmenter::is_mid_pdu`]), so the fragments of two PDUs never
//! interleave.

use crate::link::AclIn;

/// Length of the basic L2CAP header: payload length and channel identifier.
pub const HEADER_LEN: usize = 4;
/// Largest PDU the host receives, header included: an SMP Pairing Public
/// Key is 4 + 65 octets.
pub const RX_MAX: usize = 72;
/// Largest link layer payload an outgoing fragment fills: the default data
/// length.
pub const FRAGMENT_MAX: usize = 27;
/// Channel identifier of the attribute protocol.
pub const CID_ATT: u16 = 0x0004;
/// Channel identifier of the LE signalling channel.
pub const CID_SIGNALLING: u16 = 0x0005;
/// Channel identifier of the security manager.
pub const CID_SECURITY_MANAGER: u16 = 0x0006;

/// A fixed channel the host serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Channel {
    /// The attribute protocol, CID 4.
    Att,
    /// The security manager, CID 6.
    SecurityManager,
    /// The LE signalling channel, CID 5.
    Signalling,
}

/// One outgoing fragment: its payload and whether it starts the PDU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Fragment {
    /// The payload, of which the first `len` octets count.
    data:  [u8; FRAGMENT_MAX],
    /// Payload length.
    len:   u8,
    /// Whether it starts the PDU.
    start: bool,
}

/// A complete PDU received on one of the host's channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Pdu<'buf> {
    /// The channel it was received on.
    pub channel:   Channel,
    /// Whether each of its fragments was received encrypted, with a valid
    /// MIC: what the security checks of ATT take.
    pub encrypted: bool,
    /// The payload, after the L2CAP header.
    pub payload:   &'buf [u8],
}

/// Joins received fragments into PDUs, in one buffer of [`RX_MAX`] octets.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Reassembly {
    /// Whether a PDU is being received.
    active:    bool,
    /// The PDU's octets so far, header first.
    buffer:    [u8; RX_MAX],
    /// Whether each fragment so far was received encrypted.
    encrypted: bool,
    /// Octets received so far.
    len:       usize,
}

/// Renders one outgoing PDU fragment by fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Segmenter {
    /// The channel the PDU goes to.
    channel: Channel,
    /// Payload length.
    len:     u16,
    /// Octets of the PDU, header included, queued so far.
    offset:  u16,
}

impl Channel {
    /// The channel identifier.
    #[inline]
    #[must_use = "the identifier is only read"]
    pub const fn cid(self) -> u16 {
        match self {
            Self::Att => CID_ATT,
            Self::SecurityManager => CID_SECURITY_MANAGER,
            Self::Signalling => CID_SIGNALLING,
        }
    }

    /// The channel with the identifier `cid`, if the host serves it.
    #[inline]
    #[must_use = "the channel is only looked up"]
    pub const fn from_cid(cid: u16) -> Option<Self> {
        match cid {
            CID_ATT => Some(Self::Att),
            CID_SIGNALLING => Some(Self::Signalling),
            CID_SECURITY_MANAGER => Some(Self::SecurityManager),
            _ => None,
        }
    }
}

impl Fragment {
    /// The payload for the link layer.
    #[inline]
    #[must_use = "the payload is only read"]
    pub fn bytes(&self) -> &[u8] { self.data.get(..usize::from(self.len)).unwrap_or_default() }

    /// Whether it starts the PDU, for [`crate::link::Link::try_send`].
    #[inline]
    #[must_use = "the flag is only read"]
    pub const fn start(&self) -> bool { self.start }
}

impl Reassembly {
    /// Drops the PDU being received.
    const fn drop_pdu(&mut self) -> Option<Pdu<'_>> {
        self.active = false;
        self.len = 0;
        None
    }

    /// No PDU being received.
    #[inline]
    #[must_use = "the buffer is only built"]
    pub const fn new() -> Self { Self { active: false, buffer: [0; RX_MAX], encrypted: false, len: 0 } }

    /// Takes a received fragment: its payload `data`, whether it `start`s
    /// a PDU and whether it was received `encrypted`. Returns the PDU it
    /// completes, if any, on a channel the host serves.
    #[inline]
    pub fn push(&mut self, start: bool, encrypted: bool, data: &[u8]) -> Option<Pdu<'_>> {
        if start {
            // A new start drops a PDU that is still incomplete.
            self.active = true;
            self.encrypted = true;
            self.len = 0;
        } else if !self.active {
            // A continuation without a start.
            return None;
        } else {
            // A continuation of the PDU being received.
        }
        let end = self.len.saturating_add(data.len());
        let Some(target) = self.buffer.get_mut(self.len..end) else { return self.drop_pdu() };
        target.copy_from_slice(data);
        self.len = end;
        self.encrypted &= encrypted;
        let &[len0, len1, cid0, cid1] = self.buffer.first_chunk::<HEADER_LEN>().filter(|_| end >= HEADER_LEN)?;
        let expected = HEADER_LEN.saturating_add(usize::from(u16::from_le_bytes([len0, len1])));
        if expected > RX_MAX || end > expected {
            // Longer than the buffer, or than the header announces.
            return self.drop_pdu();
        }
        if end < expected {
            return None;
        }
        self.active = false;
        self.len = 0;
        let channel = Channel::from_cid(u16::from_le_bytes([cid0, cid1]))?;
        let payload = self.buffer.get(HEADER_LEN..end)?;
        Some(Pdu { channel, encrypted: self.encrypted, payload })
    }

    /// Takes a fragment the link layer received, as [`Self::push`].
    #[inline]
    pub fn push_acl(&mut self, acl: &AclIn) -> Option<Pdu<'_>> {
        self.push(acl.start(), acl.encrypted(), acl.payload())
    }
}

impl Default for Reassembly {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl Segmenter {
    /// Marks the fragment [`Self::fragment`] gave as queued, so the next
    /// call gives the one after it.
    #[inline]
    pub fn advance(&mut self) {
        let total = self.total();
        self.offset = self.offset.saturating_add(fragment_len(total, self.offset)).min(total);
    }

    /// The channel the PDU goes to.
    #[inline]
    #[must_use = "the channel is only read"]
    pub const fn channel(&self) -> Channel { self.channel }

    /// The next fragment of the PDU whose payload is `payload`, `None` once
    /// every fragment was queued or if `payload` does not have the length
    /// the segmenter was made for.
    #[inline]
    #[must_use = "the fragment is only rendered"]
    pub fn fragment(&self, payload: &[u8]) -> Option<Fragment> {
        if payload.len() != usize::from(self.len) || self.is_done() {
            return None;
        }
        let [len0, len1] = self.len.to_le_bytes();
        let [cid0, cid1] = self.channel.cid().to_le_bytes();
        let header = [len0, len1, cid0, cid1];
        let count = fragment_len(self.total(), self.offset);
        let mut data = [0_u8; FRAGMENT_MAX];
        let mut position = usize::from(self.offset);
        for slot in data.iter_mut().take(usize::from(count)) {
            let byte =
                position.checked_sub(HEADER_LEN).map_or_else(|| header.get(position), |index| payload.get(index));
            *slot = byte.copied().unwrap_or_default();
            position = position.saturating_add(1);
        }
        Some(Fragment { data, len: u8::try_from(count).unwrap_or_default(), start: self.offset == 0 })
    }

    /// Whether every fragment was queued.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn is_done(&self) -> bool { self.offset >= self.total() }

    /// Whether the PDU is part sent: its first fragment was queued and its
    /// last one not yet. No other PDU may start meanwhile.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn is_mid_pdu(&self) -> bool { self.offset > 0 && !self.is_done() }

    /// A PDU to `channel` with a payload of `payload_len` octets, `None` if it
    /// does not fit the 16-bit length field.
    #[inline]
    #[must_use = "the segmenter is only built"]
    pub fn new(channel: Channel, payload_len: usize) -> Option<Self> {
        let len = u16::try_from(payload_len.saturating_add(HEADER_LEN)).ok()?.checked_sub(4)?;
        Some(Self { channel, len, offset: 0 })
    }

    /// Length of the PDU, header included.
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation, reason = "a header of 4 fits a u16")]
    const fn total(&self) -> u16 { self.len.saturating_add(HEADER_LEN as u16) }
}

/// Length of the fragment of a PDU of `total` octets that starts at
/// `offset`.
#[expect(clippy::as_conversions, clippy::cast_possible_truncation, reason = "27 fits a u16")]
const fn fragment_len(total: u16, offset: u16) -> u16 {
    let left = total.saturating_sub(offset);
    if left > FRAGMENT_MAX as u16 { FRAGMENT_MAX as u16 } else { left }
}

#[cfg(test)] mod tests;
