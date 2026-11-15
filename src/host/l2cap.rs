//! The L2CAP fixed channels of a low energy link.
//!
//! [`Reassembly`] joins received fragments into one PDU in a single buffer of
//! [`RX_MAX`] (72) octets, the size of the largest PDU the host takes: an SMP
//! Pairing Public Key is 4 + 65 octets. A start fragment begins a new PDU and
//! drops an incomplete one. A continuation without a start, a PDU longer than
//! the buffer and a PDU with more octets than its header announces are
//! dropped. A complete PDU goes to its channel by CID: 4 (ATT), 5 (LE
//! signalling) or 6 (security manager), and with the feature `eatt` 0x0040 and
//! up for the enhanced bearers (`Channel::Eatt`); any other CID is dropped.
//! The PDU is encrypted only if each of its fragments was received encrypted.
//! With `eatt`, a PDU too long for the buffer on a bearer's CID is reported
//! (`Reassembly::take_overlong`): it is a K-frame longer than the bearer's
//! MPS, on which the channel has to be closed.
//!
//! With `eatt`, `SduRx` joins the K-frames of an enhanced bearer into its
//! SDUs (Core, Vol 3, Part A, 3.4): the first K-frame of an SDU starts with
//! the SDU's length, an SDU that one K-frame holds whole is handed on in
//! place, and one buffer of `att::ATT_MAX` (65) octets takes a split SDU, of
//! one bearer at a time.
//!
//! [`Segmenter`] renders an outgoing PDU fragment by fragment into link layer
//! payloads of up to [`FRAGMENT_MAX`] (27) octets, from the PDU's payload as
//! its owner renders it again for each fragment, so no transmit buffer holds
//! a whole PDU. A fragment is taken from it only once the link layer queued
//! it, and the engine starts no other PDU while one is part sent
//! ([`Segmenter::is_mid_pdu`]), so the fragments of two PDUs never
//! interleave. With `eatt` it also renders the K-frames of an SDU
//! (`Segmenter::kframe`), each a PDU of its own to the peer's CID.

#[cfg(feature = "eatt")]
use crate::host::{
    att::ATT_MAX,
    ecfc::{BEARERS, FIRST_CID, MPS},
};
use crate::{link::AclIn, pdu::concat_into};

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
/// The CID after the last enhanced bearer's.
#[cfg(feature = "eatt")]
const END_CID: u16 = FIRST_CID.strict_add(BEARERS.saturating_cast());
/// Length of the SDU length field of an SDU's first K-frame.
#[cfg(feature = "eatt")]
const SDU_LEN_LEN: usize = 2;

/// A fixed channel the host serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Channel {
    /// The attribute protocol, CID 4.
    Att,
    /// The enhanced ATT bearer of this index, below
    /// [`crate::host::ecfc::BEARERS`]: our CID 0x0040 plus the index.
    #[cfg(feature = "eatt")]
    Eatt(u8),
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
    /// The bearer whose CID a PDU too long for the buffer was dropped on,
    /// until [`Self::take_overlong`].
    #[cfg(feature = "eatt")]
    overlong:  Option<u8>,
}

/// Joins the K-frames of the enhanced bearers into SDUs, with one buffer for
/// an SDU split over several K-frames.
#[cfg(feature = "eatt")]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SduRx {
    /// The split SDU's octets so far.
    buffer:    [u8; ATT_MAX],
    /// Whether each of its K-frames so far was received encrypted.
    encrypted: bool,
    /// Octets received so far.
    len:       u8,
    /// The bearer whose split SDU the buffer holds, if any.
    owner:     Option<u8>,
    /// The split SDU's length, from its first K-frame.
    total:     u8,
}

/// A K-frame after which its channel is to be closed.
///
/// It breaks the rules of its channel (Core, Vol 3, Part A, 3.4.3): longer
/// than our MPS, an SDU longer than our MTU, more octets than the SDU length
/// announced, or a first K-frame shorter than the SDU length field. Or it
/// starts a second split SDU while another bearer's fills the one buffer.
#[cfg(feature = "eatt")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Violation;

/// The part of an outgoing SDU that a K-frame carries.
#[cfg(feature = "eatt")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KFrame {
    /// The peer's CID, which the header carries.
    cid:   u16,
    /// Whether it is the SDU's first K-frame, which starts with the SDU
    /// length.
    first: bool,
    /// The offset in the SDU of the first octet it carries.
    from:  u8,
    /// The SDU's length.
    sdu:   u8,
}

/// Renders one outgoing PDU fragment by fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Segmenter {
    /// The channel the PDU goes to.
    channel: Channel,
    /// For a K-frame, the part of the SDU it carries.
    #[cfg(feature = "eatt")]
    kframe:  Option<KFrame>,
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
            #[cfg(feature = "eatt")]
            Self::Eatt(bearer) => FIRST_CID.saturating_add(u16::from(bearer)),
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
            #[cfg(feature = "eatt")]
            FIRST_CID..END_CID => Some(Self::Eatt(cid.wrapping_sub(FIRST_CID).saturating_cast())),
            _ => None,
        }
    }
}

impl Fragment {
    /// The payload for the link layer.
    #[inline]
    #[must_use = "the payload is only read"]
    pub const fn bytes(&self) -> &[u8] { self.data.get(..usize::from(self.len)).unwrap_or_default() }

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
    pub const fn new() -> Self {
        Self {
            active: false,
            buffer: [0; RX_MAX],
            encrypted: false,
            len: 0,
            #[cfg(feature = "eatt")]
            overlong: None,
        }
    }

    /// Takes a received fragment: its payload `data`, whether it `start`s
    /// a PDU and whether it was received `encrypted`. Returns the PDU it
    /// completes, if any, on a channel the host serves.
    #[inline]
    pub const fn push(&mut self, start: bool, encrypted: bool, data: &[u8]) -> Option<Pdu<'_>> {
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
        let &[len0, len1, cid0, cid1] = self.buffer.first_chunk::<HEADER_LEN>().filter(const |_| end >= HEADER_LEN)?;
        let expected = HEADER_LEN.saturating_add(usize::from(u16::from_le_bytes([len0, len1])));
        if expected > RX_MAX || end > expected {
            // Longer than the buffer, or than the header announces.
            #[cfg(feature = "eatt")]
            if expected > RX_MAX
                && let Some(Channel::Eatt(bearer)) = Channel::from_cid(u16::from_le_bytes([cid0, cid1]))
            {
                self.overlong = Some(bearer);
            }
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
    pub const fn push_acl(&mut self, acl: &AclIn) -> Option<Pdu<'_>> {
        self.push(acl.start(), acl.encrypted(), acl.payload())
    }

    /// The enhanced bearer on whose CID the last PDU too long for the buffer
    /// was dropped, once: a K-frame longer than our MPS, after which the
    /// bearer is to be closed.
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the report is taken only once"]
    pub const fn take_overlong(&mut self) -> Option<u8> { self.overlong.take() }
}

impl Default for Reassembly {
    #[inline]
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "eatt")]
impl SduRx {
    /// No split SDU being received.
    #[inline]
    #[must_use = "the buffer is only built"]
    pub const fn new() -> Self { Self { buffer: [0; ATT_MAX], encrypted: false, len: 0, owner: None, total: 0 } }

    /// Takes the payload `kframe` of a K-frame received on the enhanced
    /// `bearer`, `encrypted` or not, whose credit was counted. Returns the
    /// SDU it completes, if any, and whether each of its K-frames was received
    /// encrypted: in place for an SDU the K-frame holds whole, else from the
    /// buffer.
    ///
    /// # Errors
    ///
    /// [`Violation`] if the K-frame breaks the channel's rules, or starts an
    /// SDU it does not hold whole while the buffer holds another bearer's. A
    /// split SDU of `bearer` itself is dropped then.
    #[inline]
    pub fn push<'buf>(
        &'buf mut self,
        bearer: u8,
        kframe: &'buf [u8],
        encrypted: bool,
    ) -> Result<Option<(&'buf [u8], bool)>, Violation> {
        if kframe.len() > usize::from(MPS) {
            self.release(bearer);
            return Err(Violation);
        }
        if self.owner == Some(bearer) {
            // A continuation of the bearer's split SDU.
            let start = usize::from(self.len);
            let end = start.saturating_add(kframe.len());
            let Some(target) = self.buffer.get_mut(start..end).filter(|_| end <= usize::from(self.total)) else {
                self.release(bearer);
                return Err(Violation);
            };
            target.copy_from_slice(kframe);
            self.len = end.saturating_cast();
            self.encrypted &= encrypted;
            if end < usize::from(self.total) {
                return Ok(None);
            }
            self.owner = None;
            return Ok(self.buffer.get(..end).map(|sdu| (sdu, self.encrypted)));
        }
        let Some((&[len0, len1], data)) = kframe.split_first_chunk::<SDU_LEN_LEN>() else { return Err(Violation) };
        let total = usize::from(u16::from_le_bytes([len0, len1]));
        if total > ATT_MAX || data.len() > total {
            return Err(Violation);
        }
        if data.len() == total {
            return Ok(Some((data, encrypted)));
        }
        if self.owner.is_some() {
            return Err(Violation);
        }
        let target = self.buffer.get_mut(..data.len()).ok_or(Violation)?;
        target.copy_from_slice(data);
        self.owner = Some(bearer);
        self.encrypted = encrypted;
        self.len = data.len().saturating_cast();
        self.total = total.saturating_cast();
        Ok(None)
    }

    /// Drops the split SDU of `bearer`, if the buffer holds one: the bearer
    /// closed.
    #[inline]
    pub const fn release(&mut self, bearer: u8) {
        if let Some(owner) = self.owner
            && owner == bearer
        {
            self.owner = None;
            self.len = 0;
        }
    }
}

#[cfg(feature = "eatt")]
impl Default for SduRx {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl Segmenter {
    /// Marks the fragment [`Self::fragment`] gave as queued, so the next
    /// call gives the one after it.
    #[inline]
    pub const fn advance(&mut self) {
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
        #[cfg(feature = "eatt")]
        if let Some(kframe) = self.kframe {
            return self.kframe_fragment(kframe, payload);
        }
        if payload.len() != usize::from(self.len) || self.is_done() {
            return None;
        }
        let [len0, len1] = self.len.to_le_bytes();
        let [cid0, cid1] = self.channel.cid().to_le_bytes();
        let header = [len0, len1, cid0, cid1];
        let mut data: [u8; FRAGMENT_MAX] = [0; FRAGMENT_MAX];
        // The fragment is header and payload from the offset, as far as
        // the buffer holds them.
        let offset = usize::from(self.offset);
        let len = concat_into(&mut data, &[
            header.get(offset..).unwrap_or_default(),
            payload.get(offset.saturating_sub(HEADER_LEN)..).unwrap_or_default(),
        ]);
        Some(Fragment { data, len: len.saturating_cast(), start: self.offset == 0 })
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

    /// The next K-frame of an SDU of `sdu_len` octets to the bearer's
    /// `channel`, of which `sent` octets went in earlier K-frames, for the
    /// peer's `cid` and MPS `mps`: the first K-frame carries the SDU length
    /// and up to `mps` − 2 octets of the SDU, a later one up to `mps`. `None`
    /// once the whole SDU was sent, for an SDU longer than 255 octets, or an
    /// MPS that leaves no room for a first octet.
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the segmenter is only built"]
    pub fn kframe(channel: Channel, cid: u16, sdu_len: usize, sent: usize, mps: u16) -> Option<Self> {
        let sdu = u8::try_from(sdu_len).ok()?;
        let from = u8::try_from(sent).ok()?;
        let first = sent == 0;
        let header = if first { SDU_LEN_LEN } else { 0 };
        let rest = sdu_len.checked_sub(sent).filter(|&rest| first || rest > 0)?;
        let room = usize::from(mps).checked_sub(header).filter(|&room| room > 0)?;
        let len = u16::try_from(rest.min(room).saturating_add(header)).ok()?;
        Some(Self { channel, kframe: Some(KFrame { cid, first, from, sdu }), len, offset: 0 })
    }

    /// For a K-frame, the offset in its SDU after its last octet and the SDU's
    /// length: equal for the SDU's last K-frame.
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the progress is only read"]
    pub const fn kframe_end(&self) -> Option<(usize, usize)> {
        let Some(kframe) = self.kframe else { return None };
        let header = if kframe.first { SDU_LEN_LEN } else { 0 };
        let end = usize::from(kframe.from).saturating_add(usize::from(self.len).saturating_sub(header));
        Some((end, usize::from(kframe.sdu)))
    }

    /// The next fragment of a K-frame, from the whole `sdu`; `None` once
    /// every fragment was queued or if `sdu` does not have the length the
    /// segmenter was made for.
    #[cfg(feature = "eatt")]
    fn kframe_fragment(&self, kframe: KFrame, sdu: &[u8]) -> Option<Fragment> {
        if sdu.len() != usize::from(kframe.sdu) || self.is_done() {
            return None;
        }
        let prefix = if kframe.first { SDU_LEN_LEN } else { 0 };
        let header_len = HEADER_LEN.saturating_add(prefix);
        let from = usize::from(kframe.from);
        let part = sdu.get(from..from.saturating_add(usize::from(self.len).saturating_sub(prefix)))?;
        let [len0, len1] = self.len.to_le_bytes();
        let [cid0, cid1] = kframe.cid.to_le_bytes();
        let [sdu0, sdu1] = u16::from(kframe.sdu).to_le_bytes();
        let headers = [len0, len1, cid0, cid1, sdu0, sdu1];
        let header = headers.get(..header_len)?;
        let mut data: [u8; FRAGMENT_MAX] = [0; FRAGMENT_MAX];
        let offset = usize::from(self.offset);
        let len = concat_into(&mut data, &[
            header.get(offset..).unwrap_or_default(),
            part.get(offset.saturating_sub(header_len)..).unwrap_or_default(),
        ]);
        Some(Fragment { data, len: len.saturating_cast(), start: self.offset == 0 })
    }

    /// A PDU to `channel` with a payload of `payload_len` octets, `None` if it
    /// does not fit the 16-bit length field.
    #[inline]
    #[must_use = "the segmenter is only built"]
    pub const fn new(channel: Channel, payload_len: usize) -> Option<Self> {
        let len = u16::try_from(payload_len.saturating_add(HEADER_LEN)).ok()?.checked_sub(4)?;
        Some(Self {
            channel,
            #[cfg(feature = "eatt")]
            kframe: None,
            len,
            offset: 0,
        })
    }

    /// Length of the PDU, header included.
    const fn total(self) -> u16 { self.len.saturating_add(HEADER_LEN.saturating_cast()) }
}

/// Length of the fragment of a PDU of `total` octets that starts at
/// `offset`.
const fn fragment_len(total: u16, offset: u16) -> u16 {
    total.saturating_sub(offset).min(FRAGMENT_MAX.saturating_cast())
}

#[cfg(test)] mod tests;
