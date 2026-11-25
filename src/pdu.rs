//! Link layer packet formats.

use crate::chip;
#[cfg(feature = "extended-advertising")]
use crate::radio::Phy;

/// Length of a device address.
pub const ADDRESS_LEN: usize = 6;
/// Access address of the advertising channels.
pub const ADV_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
/// CRC initial value on the advertising channels.
pub const ADV_CRC_INIT: u32 = 0x0055_5555;
/// Largest advertising channel payload.
pub const ADV_PAYLOAD_MAX: usize = 255;
/// Size of a packet buffer of the data channels and of legacy advertising:
/// header, S1 byte and the largest payload the radio accepts there.
///
/// That is 255 octets on the nRF52 chips and 37 on the nRF51. With
/// `extended-advertising` the advertising channels receive into the
/// advertiser's own buffer instead, of `HEADER_LEN` and `AUX_PAYLOAD_MAX`
/// octets.
pub const BUFFER_LEN: usize = HEADER_LEN.strict_add(1).strict_add(chip::PAYLOAD_MAX);
/// Length of a PDU header.
pub const HEADER_LEN: usize = 2;

// A packet buffer takes, as the radio's DMA writes it, the longest payload
// the untrusted length field can announce, 31 octets with the nRF51's five
// bits and 255 with the nRF52 chips' eight, and a legacy advertising PDU of up
// to 37 octets; and the radio takes a packet of the buffer's size from RAM.
const _: () = {
    let length_field_max: usize = if cfg!(feature = "nrf51") { 31 } else { 255 };
    assert!(BUFFER_LEN >= length_field_max.saturating_add(3), "the largest length field overruns a packet buffer");
    assert!(BUFFER_LEN >= HEADER_LEN.saturating_add(37), "a legacy advertising PDU overruns a packet buffer");
    assert!(BUFFER_LEN <= chip::PACKET_RAM_MAX, "a packet buffer exceeds the radio's packet in RAM");
};
/// Largest payload of an `AUX_ADV_IND` we send: 255 octets on the nRF52 chips
/// and 252 on the nRF51.
///
/// That is the largest advertising channel payload, 255 octets, as far as
/// the radio sends it from RAM after the two-octet header: S0, length and
/// payload take at most 258 octets of RAM on the nRF52 chips and 254 on the
/// nRF51.
///
/// A longer one would go on air with its full length field but a cut
/// payload, which every receiver drops for its CRC. On the nRF51, MAXLEN
/// has to admit this length for the transmission and can change only while
/// the radio is disabled, so it still holds it while the radio listens for
/// a request right after: that listen's buffer has to take
/// `HEADER_LEN + AUX_PAYLOAD_MAX` octets too.
#[cfg(feature = "extended-advertising")]
pub const AUX_PAYLOAD_MAX: usize = {
    let in_ram = chip::PACKET_RAM_MAX.strict_sub(HEADER_LEN);
    if in_ram < ADV_PAYLOAD_MAX { in_ram } else { ADV_PAYLOAD_MAX }
};
#[cfg(feature = "extended-advertising")]
const _: () = {
    assert!(
        HEADER_LEN.strict_add(AUX_PAYLOAD_MAX) <= chip::PACKET_RAM_MAX,
        "the largest AUX_ADV_IND exceeds the radio's packet in RAM"
    );
    // The listen after the `AUX_ADV_IND` receives into its buffer.
    assert!(
        usize::from(chip::ADV_MAXLEN) == AUX_PAYLOAD_MAX,
        "the advertising channels' MAXLEN does not admit exactly the largest AUX_ADV_IND"
    );
};
/// Header bit marking the receiver address as random.
const RX_ADD_RANDOM: u8 = 0x80;
/// Header bit marking the sender address as random.
const TX_ADD_RANDOM: u8 = 0x40;
/// The two most significant bits of a static random address, in its most
/// significant octet.
const STATIC_RANDOM: u8 = 0xC0;
/// Length of the ADI field.
#[cfg(feature = "extended-advertising")]
const ADI_LEN: usize = 2;
/// `AdvMode` connectable, in the octet with the extended header length
/// (Core, Vol 6, Part B, 2.3.4).
#[cfg(feature = "extended-advertising")]
const ADV_MODE_CONNECTABLE: u8 = 0x40;
/// PDU type of an extended advertisement: `ADV_EXT_IND` on the primary
/// channels, `AUX_ADV_IND` on the secondary ones.
#[cfg(feature = "extended-advertising")]
pub const ADV_EXT_IND: u8 = 0x7;
/// PDU type of the answer to an `AUX_CONNECT_REQ`.
#[cfg(feature = "extended-advertising")]
pub const AUX_CONNECT_RSP: u8 = 0x8;
/// Payload length of an `AUX_CONNECT_RSP`: the extended header with the
/// advertiser's and the initiator's address.
#[cfg(feature = "extended-advertising")]
pub const AUX_CONNECT_RSP_LEN: usize = 14;
/// Payload octets of an undirected `AUX_ADV_IND` before its advertising
/// data: the extended header length and flags, the advertiser's address and
/// the ADI.
#[cfg(feature = "extended-advertising")]
pub const AUX_HEADER_LEN: usize = 2_usize.strict_add(ADDRESS_LEN).strict_add(ADI_LEN);
/// Payload octets of a directed `AUX_ADV_IND` before its advertising data:
/// [`AUX_HEADER_LEN`] and the target's address.
#[cfg(feature = "extended-advertising")]
pub const AUX_DIRECTED_HEADER_LEN: usize = AUX_HEADER_LEN.strict_add(ADDRESS_LEN);
/// Length of the `AuxPtr` field.
#[cfg(feature = "extended-advertising")]
const AUX_PTR_LEN: usize = 3;
/// Mask of the advertising data ID in the ADI field.
#[cfg(feature = "extended-advertising")]
const DID_MASK: u16 = 0x0FFF;
/// Extended header flag: the advertiser's address.
#[cfg(feature = "extended-advertising")]
const EXT_ADV_A: u8 = 0x01;
/// Extended header flag: the ADI field.
#[cfg(feature = "extended-advertising")]
const EXT_ADI: u8 = 0x08;
/// Extended header flag: the `AuxPtr` field.
#[cfg(feature = "extended-advertising")]
const EXT_AUX_PTR: u8 = 0x10;
/// Extended header flag: the target's address.
#[cfg(feature = "extended-advertising")]
const EXT_TARGET_A: u8 = 0x02;
/// Payload length of an `ADV_EXT_IND`: the extended header length and
/// flags, the ADI and the `AuxPtr`.
#[cfg(feature = "extended-advertising")]
pub const EXT_PRIMARY_LEN: usize = 2_usize.strict_add(ADI_LEN).strict_add(AUX_PTR_LEN);
/// Largest Aux Offset, 13 bits.
#[cfg(feature = "extended-advertising")]
pub const AUX_OFFSET_MAX: u16 = 0x1FFF;
/// PDU type of a connectable undirected advertisement.
#[cfg(not(feature = "extended-advertising"))]
pub const ADV_IND: u8 = 0x0;
/// PDU type of a connectable directed advertisement.
#[cfg(not(feature = "extended-advertising"))]
pub const ADV_DIRECT_IND: u8 = 0x1;
/// PDU type of a non-connectable undirected advertisement.
#[cfg(not(feature = "extended-advertising"))]
pub const ADV_NONCONN_IND: u8 = 0x2;
/// PDU type of a scannable undirected advertisement.
#[cfg(not(feature = "extended-advertising"))]
pub const ADV_SCAN_IND: u8 = 0x6;
/// PDU type of a connection request: `CONNECT_IND`, or with extended
/// advertising `AUX_CONNECT_REQ`, which has the same layout.
const CONNECT_IND: u8 = 0x5;
/// Payload length of a connection request.
pub(crate) const CONNECT_IND_LEN: u8 = 34;
/// Largest connection interval in units of 1.25 ms.
const INTERVAL_MAX: u16 = 3200;
/// Smallest connection interval in units of 1.25 ms.
const INTERVAL_MIN: u16 = 6;
/// Largest peripheral latency.
const LATENCY_MAX: u16 = 499;
/// Largest hop increment.
const HOP_MAX: u8 = 16;
/// Smallest hop increment.
const HOP_MIN: u8 = 5;
/// Advertising PDU header bit: channel selection algorithm 2 supported, or
/// chosen in a connection request.
const CH_SEL: u8 = 0x20;
/// Mask of the PDU type in the first header byte.
const PDU_TYPE_MASK: u8 = 0x0F;
/// PDU type of a scan request.
#[cfg(not(feature = "extended-advertising"))]
const SCAN_REQ: u8 = 0x3;
/// Payload length of a scan request.
#[cfg(not(feature = "extended-advertising"))]
const SCAN_REQ_LEN: u8 = 12;
/// PDU type of a scan response.
#[cfg(not(feature = "extended-advertising"))]
pub const SCAN_RSP: u8 = 0x4;
/// Largest supervision timeout in units of 10 ms.
const TIMEOUT_MAX: u16 = 3200;
/// Smallest supervision timeout in units of 10 ms.
const TIMEOUT_MIN: u16 = 10;
/// Largest transmit window size in units of 1.25 ms.
const WIN_SIZE_MAX: u8 = 8;

/// Data PDU header bit: next expected sequence number.
pub const NESN: u8 = 0x04;
/// Data PDU header bit: sequence number.
pub const SN: u8 = 0x08;
/// Data PDU header bit: more data.
pub const MD: u8 = 0x10;
/// Mask of the logical link identifier in the data PDU header.
pub const LLID_MASK: u8 = 0x03;

/// Logical link identifier of a data PDU.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Llid {
    /// Continuation fragment of an L2CAP message, or an empty PDU.
    Continuation,
    /// LL control PDU.
    Control,
    /// Start of an L2CAP message.
    Start,
}

impl Llid {
    /// The header bits.
    #[inline]
    #[must_use = "the bits are only computed"]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Continuation => 1,
            Self::Start => 2,
            Self::Control => 3,
        }
    }
}

/// A device address with its type.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
#[non_exhaustive]
pub struct Peer {
    /// The address, least significant octet first.
    pub address: [u8; ADDRESS_LEN],
    /// Whether the address is random.
    pub random:  bool,
}

impl Peer {
    /// A device address with its type.
    #[inline]
    #[must_use = "the address is only built"]
    pub const fn new(address: [u8; ADDRESS_LEN], random: bool) -> Self { Self { address, random } }
}

/// An identity address: a [`Peer`] that is a public address, or a static
/// random one (the two most significant bits set), and not zero.
///
/// A bond keeps only such an address: a resolvable or non-resolvable private
/// address changes, so a bond with it would not find the central again.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
pub struct IdentityAddress(Peer);

impl IdentityAddress {
    /// `peer` as an identity address, or `None` if it is zero, or random
    /// but not static.
    #[inline]
    #[must_use = "the address is only checked"]
    pub const fn new(peer: Peer) -> Option<Self> {
        let [.., top] = peer.address;
        if peer.address == [0; ADDRESS_LEN] || (peer.random && top & STATIC_RANDOM != STATIC_RANDOM) {
            None
        } else {
            Some(Self(peer))
        }
    }

    /// The address with its type.
    #[inline]
    #[must_use = "the address is only read"]
    pub const fn peer(self) -> Peer { self.0 }

    /// `peer`, which a test gives as an identity address; it panics if it is
    /// none.
    #[cfg(test)]
    pub(crate) const fn valid(peer: Peer) -> Self {
        assert!(Self::new(peer).is_some(), "not an identity address");
        Self(peer)
    }
}

/// An advertising channel PDU as the radio sends it: header, then payload,
/// in a buffer of `N` bytes.
pub struct Advertisement<const N: usize> {
    /// Header and payload.
    bytes: [u8; N],
}

/// A PDU of legacy advertising.
#[cfg(not(feature = "extended-advertising"))]
pub type LegacyAdvertisement = Advertisement<{ HEADER_LEN.strict_add(37) }>;

/// An `ADV_EXT_IND` that points to the `AUX_ADV_IND` ([`ext_primary`]).
#[cfg(feature = "extended-advertising")]
pub type ExtPrimary = Advertisement<{ HEADER_LEN.strict_add(EXT_PRIMARY_LEN) }>;

/// An `AUX_ADV_IND` with up to the largest payload the chip sends,
/// [`AUX_PAYLOAD_MAX`] ([`aux_undirected`], [`aux_directed`]).
#[cfg(feature = "extended-advertising")]
pub type AuxAdvertisement = Advertisement<{ HEADER_LEN.strict_add(AUX_PAYLOAD_MAX) }>;

/// An `AUX_CONNECT_RSP` ([`aux_connect_rsp`]).
#[cfg(feature = "extended-advertising")]
pub type AuxConnectRsp = Advertisement<{ HEADER_LEN.strict_add(AUX_CONNECT_RSP_LEN) }>;

/// The `AdvDataInfo` field of extended advertising (Core, Vol 6, Part B,
/// 2.3.4.4): the advertising set ID (SID) and the advertising data ID (DID).
#[cfg(feature = "extended-advertising")]
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
#[non_exhaustive]
pub struct Adi {
    /// The DID in bits 0 to 11, the SID in bits 12 to 15.
    bits: u16,
}

#[cfg(feature = "extended-advertising")]
impl Adi {
    /// The advertising data ID, 12 bits.
    #[inline]
    #[must_use = "the ID is only read"]
    pub const fn did(self) -> u16 { self.bits & DID_MASK }

    /// The field of the advertising set `sid` (its four low bits) with the
    /// advertising data ID `did` (its twelve low bits).
    #[inline]
    #[must_use = "the field is only built"]
    pub const fn new(sid: u8, did: u16) -> Self { Self { bits: did & DID_MASK | u16::from(sid & 0x0F).strict_shl(12) } }

    /// The same set with a new advertising data ID from `random`, neither
    /// the current one nor that of `used`, the field last sent: the DID
    /// changes to a random value that is not the most recently used one each
    /// time the data changes (Core, Vol 6, Part B, 4.4.2.11), also when it
    /// changes twice before the next advertising event. A random value that
    /// is one of the two moves on to the next value that is neither.
    #[inline]
    #[must_use = "the field is only built"]
    pub const fn renewed(self, random: u16, used: Self) -> Self {
        let past = const |did: u16| {
            if did == self.did() || did == used.did() { did.wrapping_add(1) & DID_MASK } else { did }
        };
        // Two steps at most: the second avoids the other of the two values.
        Self::new(self.sid(), past(past(random & DID_MASK)))
    }

    /// The advertising set ID, 4 bits.
    #[inline]
    #[must_use = "the ID is only read"]
    pub const fn sid(self) -> u8 { self.bits.wrapping_shr(12).saturating_cast() }

    /// The field's two octets, least significant first.
    #[inline]
    #[must_use = "the octets are only computed"]
    pub const fn to_bytes(self) -> [u8; ADI_LEN] { self.bits.to_le_bytes() }
}

/// The `AuxPtr` field of an `ADV_EXT_IND` (Core, Vol 6, Part B, 2.3.4.5): the
/// secondary channel, clock accuracy, offset in units of 30 us and PHY of the
/// `AUX_ADV_IND`.
#[cfg(feature = "extended-advertising")]
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct AuxPtr {
    /// CA: the advertiser's clock is within 50 ppm until the auxiliary
    /// packet, rather than 500.
    pub accurate: bool,
    /// The secondary channel index, 0 to 36.
    pub channel:  u8,
    /// Aux Offset in units of 30 us (Offset Units 0) from the start of the
    /// packet with the field, 13 bits: the auxiliary packet starts within
    /// one unit after it.
    pub offset:   u16,
    /// The PHY of the auxiliary packet.
    pub phy:      Phy,
}

#[cfg(feature = "extended-advertising")]
impl AuxPtr {
    /// A pointer to channel `channel`, `offset` units of 30 us later, on
    /// `phy`, with a clock accuracy of 500 ppm.
    #[inline]
    #[must_use = "the field is only built"]
    pub const fn new(channel: u8, offset: u16, phy: Phy) -> Self { Self { accurate: false, channel, offset, phy } }

    /// The field's three octets: channel index, CA and Offset Units 0, then
    /// Aux Offset and Aux PHY least significant octet first.
    #[inline]
    #[must_use = "the octets are only computed"]
    pub const fn to_bytes(self) -> [u8; AUX_PTR_LEN] {
        let phy: u16 = match self.phy {
            Phy::M1 => 0,
            Phy::M2 => 1,
        };
        let [offset0, offset1] = (self.offset & AUX_OFFSET_MAX | phy.strict_shl(13)).to_le_bytes();
        [self.channel & 0x3F | if self.accurate { 0x40 } else { 0 }, offset0, offset1]
    }
}

impl<const N: usize> Advertisement<N> {
    /// The PDU bytes up to the end of the payload.
    #[inline]
    #[must_use = "the bytes are only borrowed"]
    pub const fn as_bytes(&self) -> &[u8] {
        const { assert!(N >= HEADER_LEN, "an advertising PDU holds its header") };
        let len = usize::from(self.bytes[1]);
        self.bytes.get(..HEADER_LEN.saturating_add(len)).unwrap_or_default()
    }

    /// A PDU with `header` and the payload `parts` in order. Payload beyond
    /// the buffer is cut off.
    fn build(header: u8, parts: &[&[u8]]) -> Self {
        const { assert!(N >= HEADER_LEN, "an advertising PDU holds its header") };
        let mut bytes: [u8; N] = [0; N];
        let (_, after_header) = bytes.split_at_mut(HEADER_LEN);
        let (payload, _) = after_header.split_at_mut(after_header.len().min(ADV_PAYLOAD_MAX));
        let len = concat_into(payload, parts);
        bytes[0] = header;
        bytes[1] = len.saturating_cast();
        Self { bytes }
    }

    /// A connectable directed advertisement from `advertiser` to `target`.
    #[cfg(not(feature = "extended-advertising"))]
    #[inline]
    #[must_use = "the PDU is only built"]
    pub fn directed(advertiser: Peer, target: Peer) -> Self {
        let header = ADV_DIRECT_IND
            | CH_SEL
            | if advertiser.random { TX_ADD_RANDOM } else { 0 }
            | if target.random { RX_ADD_RANDOM } else { 0 };
        Self::build(header, &[&advertiser.address, &target.address])
    }

    /// The whole buffer: the PDU, then zeros. The extended advertising
    /// event sends an `AUX_ADV_IND` from it and receives the request after
    /// it into the same buffer, which holds the longest packet the
    /// advertising channels admit.
    #[cfg(feature = "extended-advertising")]
    #[inline]
    #[must_use = "the buffer is only taken"]
    pub const fn into_buffer(self) -> [u8; N] { self.bytes }

    /// An undirected advertisement or scan response of PDU type `kind` from
    /// `advertiser`. Data beyond 31 bytes is cut off.
    #[cfg(not(feature = "extended-advertising"))]
    #[inline]
    #[must_use = "the PDU is only built"]
    pub fn undirected(kind: u8, advertiser: Peer, data: &[u8]) -> Self {
        let ch_sel = if kind == ADV_IND { CH_SEL } else { 0 };
        let header = kind | ch_sel | if advertiser.random { TX_ADD_RANDOM } else { 0 };
        Self::build(header, &[&advertiser.address, data])
    }
}

/// Parameters of a connection request.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ConnectInd {
    /// Access address of the connection.
    pub access_address:   u32,
    /// Used data channels, one bit per channel.
    pub channel_map:      [u8; 5],
    /// CRC initial value of the connection.
    pub crc_init:         u32,
    /// The central chose channel selection algorithm 2.
    pub csa2:             bool,
    /// Hop increment of channel selection algorithm 1.
    pub hop:              u8,
    /// Address of the central.
    pub initiator:        [u8; ADDRESS_LEN],
    /// Whether [`Self::initiator`] is a random address.
    pub initiator_random: bool,
    /// Connection interval in units of 1.25 ms.
    pub interval:         u16,
    /// Peripheral latency in connection events.
    pub latency:          u16,
    /// Central sleep clock accuracy field.
    pub sca:              u8,
    /// Central sleep clock accuracy in ppm.
    pub sca_ppm:          u32,
    /// Supervision timeout in units of 10 ms.
    pub timeout:          u16,
    /// Transmit window offset in units of 1.25 ms.
    pub win_offset:       u16,
    /// Transmit window size in units of 1.25 ms.
    pub win_size:         u8,
}

impl ConnectInd {
    /// The central as a device address with its type.
    #[inline]
    #[must_use = "the address is only read"]
    pub const fn central(&self) -> Peer { Peer::new(self.initiator, self.initiator_random) }

    /// Whether the parameters are within the ranges of the specification.
    fn is_valid(&self) -> bool {
        let timing = ParamCheck {
            interval:   self.interval,
            latency:    self.latency,
            timeout:    self.timeout,
            win_offset: self.win_offset,
            win_size:   self.win_size,
        };
        timing.is_valid()
            && (HOP_MIN..=HOP_MAX).contains(&self.hop)
            && valid_channel_map(self.channel_map)
            && valid_access_address(self.access_address)
    }

    /// Parses a received `CONNECT_IND`. Returns `None` unless it is a
    /// connection request to `advertiser` with valid parameters.
    #[cfg(not(feature = "extended-advertising"))]
    #[inline]
    #[must_use = "the request is only parsed"]
    pub fn parse(pdu: &[u8], advertiser: Peer) -> Option<Self> { Self::request(pdu, advertiser, false) }

    /// Parses a received `AUX_CONNECT_REQ`, which has the layout of a
    /// `CONNECT_IND` (Core, Vol 6, Part B, 2.3.3.1). Returns `None` unless
    /// it is a connection request to `advertiser` with valid parameters. Its
    /// `ChSel` bit is reserved, and the connection uses channel selection
    /// algorithm 2 (4.5): [`Self::csa2`] is set.
    #[cfg(feature = "extended-advertising")]
    #[inline]
    #[must_use = "the request is only parsed"]
    pub fn parse_aux(pdu: &[u8], advertiser: Peer) -> Option<Self> { Self::request(pdu, advertiser, true) }

    /// Parses a connection request to `advertiser`, of extended advertising
    /// if `aux`: channel selection algorithm 2 then, otherwise the one the
    /// `ChSel` bit chose.
    #[inline]
    fn request(pdu: &[u8], advertiser: Peer, aux: bool) -> Option<Self> {
        let (
            Some([kind, len]),
            Some(initiator),
            Some(target),
            Some(access_address),
            Some([crc0, crc1, crc2]),
            Some([win_size, offset0, offset1, interval0, interval1, latency0, latency1, timeout0, timeout1]),
            Some(channel_map),
            Some([hop_sca]),
        ) = (
            field::<2>(pdu, 0),
            field::<ADDRESS_LEN>(pdu, 2),
            field::<ADDRESS_LEN>(pdu, 8),
            field::<4>(pdu, 14),
            field::<3>(pdu, 18),
            field::<9>(pdu, 21),
            field::<5>(pdu, 30),
            field::<1>(pdu, 35),
        )
        else {
            return None;
        };
        if kind & PDU_TYPE_MASK != CONNECT_IND
            || len != CONNECT_IND_LEN
            || Peer::new(target, kind & RX_ADD_RANDOM != 0) != advertiser
        {
            return None;
        }
        let request = Self {
            access_address: u32::from_le_bytes(access_address),
            channel_map,
            crc_init: u32::from_le_bytes([crc0, crc1, crc2, 0]),
            csa2: aux || kind & CH_SEL != 0,
            hop: hop_sca & 0x1F,
            initiator,
            initiator_random: kind & TX_ADD_RANDOM != 0,
            interval: u16::from_le_bytes([interval0, interval1]),
            latency: u16::from_le_bytes([latency0, latency1]),
            sca: hop_sca.wrapping_shr(5),
            sca_ppm: sca_ppm(hop_sca.wrapping_shr(5)),
            timeout: u16::from_le_bytes([timeout0, timeout1]),
            win_offset: u16::from_le_bytes([offset0, offset1]),
            win_size,
        };
        request.is_valid().then_some(request)
    }
}

/// Connection timing to check against the ranges of the specification, both
/// when connecting and when updating an existing link. Named fields keep the
/// values of equal type from being swapped.
#[derive(Clone, Copy)]
pub(crate) struct ParamCheck {
    /// Connection interval in units of 1.25 ms.
    pub interval:   u16,
    /// Peripheral latency in connection events.
    pub latency:    u16,
    /// Supervision timeout in units of 10 ms.
    pub timeout:    u16,
    /// Transmit window offset in units of 1.25 ms.
    pub win_offset: u16,
    /// Transmit window size in units of 1.25 ms.
    pub win_size:   u8,
}

impl ParamCheck {
    /// Whether the timing is within the ranges of the specification.
    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        let Self { interval, latency, timeout, win_offset, win_size } = self;
        (INTERVAL_MIN..=INTERVAL_MAX).contains(&interval)
            && (TIMEOUT_MIN..=TIMEOUT_MAX).contains(&timeout)
            && latency <= LATENCY_MAX
            && u32::from(latency).saturating_add(1).saturating_mul(u32::from(interval))
                < u32::from(timeout).saturating_mul(4)
            && (1..=WIN_SIZE_MAX).contains(&win_size)
            && u16::from(win_size) < interval
            && win_offset <= interval
    }
}

/// Whether a data channel map has at least two channels and no reserved bits.
pub(crate) fn valid_channel_map(map: [u8; 5]) -> bool {
    map[4] & 0xE0 == 0 && map.iter().map(|byte| byte.count_ones()).sum::<u32>() >= 2
}

/// LE 1M data access address constraints (Core, Vol 6, Part B, 2.1.2).
fn valid_access_address(address: u32) -> bool {
    let bytes = address.to_le_bytes();
    let transitions = address ^ address.wrapping_shr(1);
    let mut run: u8 = 1;
    for bit in 1..u32::BITS {
        if (address.unbounded_shr(bit) ^ address.unbounded_shr(bit.saturating_sub(1))) & 1 == 0 {
            run = run.saturating_add(1);
            if run > 6 {
                return false;
            }
        } else {
            run = 1;
        }
    }
    (address ^ ADV_ACCESS_ADDRESS).count_ones() > 1
        && !bytes.iter().all(|byte| Some(byte) == bytes.first())
        && (transitions & 0x7FFF_FFFF).count_ones() <= 24
        && (transitions.wrapping_shr(26) & 0x1F).count_ones() >= 2
}

/// The scanner of a received scan request to `advertiser`, if it is one.
#[cfg(not(feature = "extended-advertising"))]
#[inline]
#[must_use = "the request is only checked"]
pub const fn scan_request(pdu: &[u8], advertiser: Peer) -> Option<Peer> {
    let (Some([header, len]), Some(scanner), Some(target)) =
        (field::<2>(pdu, 0), field::<ADDRESS_LEN>(pdu, 2), field::<ADDRESS_LEN>(pdu, 8))
    else {
        return None;
    };
    (header & PDU_TYPE_MASK == SCAN_REQ
        && len == SCAN_REQ_LEN
        && Peer::new(target, header & RX_ADD_RANDOM != 0) == advertiser)
        .then(const || Peer::new(scanner, header & TX_ADD_RANDOM != 0))
}

/// Whether an advertising channel PDU header is that of a scan request,
/// whatever else the packet holds.
#[cfg(not(feature = "extended-advertising"))]
#[inline]
#[must_use = "the type is only checked"]
pub const fn is_scan_request(header: u8) -> bool { header & PDU_TYPE_MASK == SCAN_REQ }

/// An `ADV_EXT_IND` of connectable advertising with the ADI `adi` and the
/// pointer `aux` to the `AUX_ADV_IND`.
///
/// It holds no address (Core, Vol 6, Part B, 2.3.1.5), and its header
/// leaves `ChSel`, `TxAdd` and `RxAdd` zero.
#[cfg(feature = "extended-advertising")]
#[inline]
#[must_use = "the PDU is only built"]
pub fn ext_primary(adi: Adi, aux: AuxPtr) -> ExtPrimary {
    ExtPrimary::build(ADV_EXT_IND, &[
        &extended_header(ADV_MODE_CONNECTABLE, EXT_ADI | EXT_AUX_PTR),
        &adi.to_bytes(),
        &aux.to_bytes(),
    ])
}

/// A connectable undirected `AUX_ADV_IND` from `advertiser` with the ADI
/// `adi` and the advertising data `data` (Core, Vol 6, Part B, 2.3.1.6).
///
/// Data beyond the largest payload, [`AUX_PAYLOAD_MAX`] after
/// [`AUX_HEADER_LEN`] octets, is cut off.
#[cfg(feature = "extended-advertising")]
#[inline]
#[must_use = "the PDU is only built"]
pub fn aux_undirected(advertiser: Peer, adi: Adi, data: &[u8]) -> AuxAdvertisement {
    let header = ADV_EXT_IND | if advertiser.random { TX_ADD_RANDOM } else { 0 };
    AuxAdvertisement::build(header, &[
        &extended_header(ADV_MODE_CONNECTABLE, EXT_ADV_A | EXT_ADI),
        &advertiser.address,
        &adi.to_bytes(),
        data,
    ])
}

/// A connectable directed `AUX_ADV_IND` from `advertiser` to `target` with
/// the ADI `adi` and the advertising data `data`.
///
/// Data beyond the largest payload, [`AUX_PAYLOAD_MAX`] after
/// [`AUX_DIRECTED_HEADER_LEN`] octets, is cut off.
#[cfg(feature = "extended-advertising")]
#[inline]
#[must_use = "the PDU is only built"]
pub fn aux_directed(advertiser: Peer, target: Peer, adi: Adi, data: &[u8]) -> AuxAdvertisement {
    let header =
        ADV_EXT_IND | if advertiser.random { TX_ADD_RANDOM } else { 0 } | if target.random { RX_ADD_RANDOM } else { 0 };
    AuxAdvertisement::build(header, &[
        &extended_header(ADV_MODE_CONNECTABLE, EXT_ADV_A | EXT_TARGET_A | EXT_ADI),
        &advertiser.address,
        &target.address,
        &adi.to_bytes(),
        data,
    ])
}

/// The `AUX_CONNECT_RSP` of `advertiser` to the initiator `initiator`
/// (Core, Vol 6, Part B, 2.3.3.2): `AdvMode` zero, the two addresses, `RxAdd`
/// for the initiator's.
#[cfg(feature = "extended-advertising")]
#[inline]
#[must_use = "the PDU is only built"]
pub fn aux_connect_rsp(advertiser: Peer, initiator: Peer) -> AuxConnectRsp {
    let header = AUX_CONNECT_RSP
        | if advertiser.random { TX_ADD_RANDOM } else { 0 }
        | if initiator.random { RX_ADD_RANDOM } else { 0 };
    AuxConnectRsp::build(header, &[
        &extended_header(0, EXT_ADV_A | EXT_TARGET_A),
        &advertiser.address,
        &initiator.address,
    ])
}

/// The initiator of a received `AUX_CONNECT_REQ`: its `InitA` and `TxAdd`,
/// if `pdu` has the type and length of a connection request.
///
/// A quick look within the interframe space, for the `AUX_CONNECT_RSP`
/// ([`retarget`]); [`ConnectInd::parse_aux`] checks the whole request.
#[cfg(feature = "extended-advertising")]
#[inline]
#[must_use = "the address is only read"]
pub const fn aux_connect_initiator(pdu: &[u8]) -> Option<Peer> {
    let (Some([header, len]), Some(initiator)) = (field::<2>(pdu, 0), field::<ADDRESS_LEN>(pdu, 2)) else {
        return None;
    };
    (header & PDU_TYPE_MASK == CONNECT_IND && len == CONNECT_IND_LEN)
        .then(const || Peer::new(initiator, header & TX_ADD_RANDOM != 0))
}

/// Puts `initiator` in place of the initiator of `response`.
///
/// That is the `TargetA` field, its last six octets, and `RxAdd`: a prebuilt
/// response gets the address of the `AUX_CONNECT_REQ` this way, within the
/// interframe space.
#[cfg(feature = "extended-advertising")]
#[inline]
pub fn retarget(response: &mut AuxConnectRsp, initiator: Peer) {
    response.bytes[0] = response.bytes[0] & !RX_ADD_RANDOM | if initiator.random { RX_ADD_RANDOM } else { 0 };
    let (_, target) = response.bytes.rsplit_array_mut::<ADDRESS_LEN>();
    *target = initiator.address;
}

/// The octet with the extended header length and `adv_mode`, and the flags
/// octet `flags`: the length counts the flags octet and the fields the flags
/// announce.
#[cfg(feature = "extended-advertising")]
const fn extended_header(adv_mode: u8, flags: u8) -> [u8; 2] {
    let field = const |flag: u8, field_len: usize| if flags & flag != 0 { field_len } else { 0 };
    let len: u8 = 1_usize
        .strict_add(field(EXT_ADV_A, ADDRESS_LEN))
        .strict_add(field(EXT_TARGET_A, ADDRESS_LEN))
        .strict_add(field(EXT_ADI, ADI_LEN))
        .strict_add(field(EXT_AUX_PTR, AUX_PTR_LEN))
        .strict_cast();
    [len | adv_mode, flags]
}

/// Copies `parts` in order into the start of `target`, as far as it holds
/// them, and returns the number of octets copied.
pub(crate) fn concat_into(target: &mut [u8], parts: &[&[u8]]) -> usize {
    let mut rest = target;
    let mut len: usize = 0;
    for part in parts {
        let (head, tail) = rest.split_at_mut(part.len().min(rest.len()));
        head.copy_from_slice(part.get(..head.len()).unwrap_or_default());
        len = len.saturating_add(head.len());
        rest = tail;
    }
    len
}

/// `N` bytes of `bytes` from `offset`, if present.
#[inline]
#[must_use = "the bytes are only copied"]
pub const fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..).and_then(<[u8]>::first_chunk::<N>).copied()
}

/// Sleep clock accuracy in ppm for a SCA field value.
const fn sca_ppm(field: u8) -> u32 {
    match field {
        0 => 500,
        1 => 250,
        2 => 150,
        3 => 100,
        4 => 75,
        5 => 50,
        6 => 30,
        _ => 20,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_channel_maps_are_rejected() {
        assert!(!valid_channel_map([0; 5]));
        assert!(!valid_channel_map([1, 0, 0, 0, 0]));
        assert!(!valid_channel_map([3, 0, 0, 0, 0x80]));
        assert!(valid_channel_map([3, 0, 0, 0, 0]));
        assert!(valid_channel_map([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]));
    }

    #[test]
    fn supervision_timeout_must_exceed_twice_maximum_latency() {
        assert!(!ParamCheck { interval: 40, latency: 0, timeout: 10, win_offset: 0, win_size: 1 }.is_valid());
        assert!(ParamCheck { interval: 39, latency: 0, timeout: 10, win_offset: 0, win_size: 1 }.is_valid());
        assert!(!ParamCheck { interval: 12, latency: 500, timeout: 3200, win_offset: 0, win_size: 1 }.is_valid());
        assert!(!ParamCheck { interval: 5, latency: 0, timeout: 100, win_offset: 0, win_size: 1 }.is_valid());
        assert!(!ParamCheck { interval: 12, latency: 0, timeout: 100, win_offset: 0, win_size: 0 }.is_valid());
        assert!(!ParamCheck { interval: 12, latency: 0, timeout: 100, win_offset: 13, win_size: 1 }.is_valid());
        assert!(ParamCheck { interval: 12, latency: 30, timeout: 600, win_offset: 0, win_size: 1 }.is_valid());
    }

    #[test]
    fn advertising_and_weak_access_addresses_are_rejected() {
        assert!(!valid_access_address(ADV_ACCESS_ADDRESS));
        for bit in 0..32 {
            assert!(!valid_access_address(ADV_ACCESS_ADDRESS ^ 1_u32.unbounded_shl(bit)));
        }
        for address in [0, u32::MAX, 0xAAAA_AAAA, 0x0000_5678, 0xFF00_7F00] {
            assert!(!valid_access_address(address));
        }
        assert!(valid_access_address(0x9A32_8370));
    }

    /// A connection request from the initiator `[2; 6]`, random, to `peer`,
    /// with valid parameters and the header `header`.
    fn connection_request(header: u8, peer: Peer) -> [u8; 36] {
        let mut bytes = [0; 36];
        bytes[0] = header;
        bytes[1] = CONNECT_IND_LEN;
        bytes[2..8].copy_from_slice(&[2; 6]);
        bytes[8..14].copy_from_slice(&peer.address);
        bytes[14..18].copy_from_slice(&0x9A32_8370_u32.to_le_bytes());
        bytes[21] = 1;
        bytes[24] = 12;
        bytes[28..30].copy_from_slice(&600_u16.to_le_bytes());
        bytes[30..35].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
        bytes[35] = 5;
        bytes
    }

    #[cfg(not(feature = "extended-advertising"))]
    #[test]
    fn truncated_scan_and_connection_requests_never_parse() {
        let peer = Peer::new([1; 6], true);
        let mut bytes = connection_request(CONNECT_IND | TX_ADD_RANDOM | RX_ADD_RANDOM, peer);
        assert!(!ConnectInd::parse(&bytes, peer).unwrap().csa2);
        bytes[0] |= CH_SEL;
        assert!(ConnectInd::parse(&bytes, peer).unwrap().csa2);
        for len in 0..bytes.len() {
            assert!(ConnectInd::parse(&bytes[..len], peer).is_none());
        }
        bytes[0] = SCAN_REQ | RX_ADD_RANDOM;
        bytes[1] = SCAN_REQ_LEN;
        for len in 0..14 {
            assert!(scan_request(&bytes[..len], peer).is_none());
        }
        assert!(scan_request(&bytes[..14], peer).is_some());
        assert!(scan_request(&bytes[..14], Peer::new([2; 6], true)).is_none());
    }

    #[cfg(not(feature = "extended-advertising"))]
    #[test]
    fn connectable_advertisements_offer_channel_selection_algorithm_2() {
        let peer = Peer::new([1; 6], true);
        assert_eq!(LegacyAdvertisement::undirected(ADV_IND, peer, &[]).bytes[0] & CH_SEL, CH_SEL);
        assert_eq!(LegacyAdvertisement::directed(peer, peer).bytes[0] & CH_SEL, CH_SEL);
        assert_eq!(LegacyAdvertisement::undirected(ADV_NONCONN_IND, peer, &[]).bytes[0] & CH_SEL, 0);
        assert_eq!(LegacyAdvertisement::undirected(SCAN_RSP, peer, &[]).bytes[0] & CH_SEL, 0);
    }

    /// Our address in the extended advertising tests: random.
    #[cfg(feature = "extended-advertising")]
    const OWN: Peer = Peer::new([1, 2, 3, 4, 5, 6], true);

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn the_primary_pdu_carries_the_adi_and_the_pointer_to_the_auxiliary_one() {
        // The design's sample: ADI 0x0ABC, channel 36, 33 units of 30 us,
        // LE 1M. Header: ADV_EXT_IND, ChSel, TxAdd and RxAdd zero; 7 octets;
        // extended header length 6 and AdvMode connectable; flags ADI and
        // AuxPtr (Core, Vol 6, Part B, 2.3.1.5 and 2.3.4).
        let primary = ext_primary(Adi::new(0, 0x0ABC), AuxPtr::new(36, 33, Phy::M1));
        assert_eq!(primary.as_bytes(), [0x07, 0x07, 0x46, 0x18, 0xBC, 0x0A, 0x24, 0x21, 0x00]);
        assert_eq!(primary.as_bytes().len(), HEADER_LEN + EXT_PRIMARY_LEN);
        // Aux PHY in the top three bits: LE 2M is 1. CA is bit 6 of the
        // channel octet, Offset Units bit 7, always 0 (30 us).
        let mut aux = AuxPtr::new(5, AUX_OFFSET_MAX, Phy::M2);
        assert_eq!(aux.to_bytes(), [0x05, 0xFF, 0x3F]);
        aux.accurate = true;
        assert_eq!(aux.to_bytes(), [0x45, 0xFF, 0x3F]);
        // Out of range fields do not spill into their neighbours.
        assert_eq!(AuxPtr::new(0xFF, 0xFFFF, Phy::M1).to_bytes(), [0x3F, 0xFF, 0x1F]);
        assert_eq!(ext_primary(Adi::new(3, 1), AuxPtr::new(0, 15, Phy::M2)).as_bytes()[4..], [
            0x01, 0x30, 0x00, 0x0F, 0x20
        ]);
    }

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn the_adi_keeps_its_set_and_renews_its_data_id_to_another_value() {
        let adi = Adi::new(0, 0x0ABC);
        assert_eq!((adi.sid(), adi.did(), adi.to_bytes()), (0, 0x0ABC, [0xBC, 0x0A]));
        assert_eq!(Adi::new(0x1F, 0xFFFF).to_bytes(), [0xFF, 0xFF]);
        assert_eq!(Adi::new(0x1F, 0xFFFF).sid(), 0x0F);
        // A random value other than the current DID is taken as it is, its
        // twelve low bits; the current DID itself is never taken again.
        assert_eq!(adi.renewed(0x1234, adi).did(), 0x0234);
        assert_eq!(adi.renewed(0x0ABC, adi).did(), 0x0ABD);
        assert_eq!(adi.renewed(0xFABC, adi).did(), 0x0ABD);
        assert_eq!(adi.renewed(0x0ABD, adi).did(), 0x0ABD);
        assert!(Adi::new(9, 0x0FFF).renewed(0x0FFF, Adi::new(9, 0x0FFF)) == Adi::new(9, 0));
        // Nor the DID last sent, when the data changed again before it was
        // replaced on air: sent 0x0ABC, renewed to 0x0123 that never went
        // out, then renewed again.
        let unsent = Adi::new(0, 0x0123);
        assert_eq!(unsent.renewed(0x0ABC, adi).did(), 0x0ABD);
        assert_eq!(unsent.renewed(0x0123, adi).did(), 0x0124);
        assert_eq!(Adi::new(0, 0x0ABD).renewed(0x0ABC, adi).did(), 0x0ABE);
        assert_eq!(Adi::new(0, 0x0ABD).renewed(0x0ABD, adi).did(), 0x0ABE);
        assert_eq!(adi.renewed(0x0ABC, Adi::new(0, 0x0ABD)).did(), 0x0ABE);
        for random in 0..=u16::MAX {
            for used in [0x0123, 0x0124, 0x0122, 0x0FFF] {
                let renewed = Adi::new(5, 0x0123).renewed(random, Adi::new(5, used));
                assert!(renewed.did() != 0x0123 && renewed.did() != used && renewed.sid() == 5);
            }
        }
    }

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn auxiliary_pdus_carry_the_addresses_the_adi_and_the_data() {
        let adi = Adi::new(0, 0x0ABC);
        // Undirected: AUX_ADV_IND with TxAdd, 10 + 3 octets; extended header
        // length 9 and AdvMode connectable; flags AdvA and ADI.
        let undirected = aux_undirected(OWN, adi, &[2, 1, 6]);
        assert_eq!(undirected.as_bytes(), [0x47, 13, 0x49, 0x09, 1, 2, 3, 4, 5, 6, 0xBC, 0x0A, 2, 1, 6]);
        // Directed to a public address: no RxAdd, 16 + 3 octets; extended
        // header length 15; flags AdvA, TargetA and ADI.
        let central = Peer::new([0x11, 0x12, 0x13, 0x14, 0x15, 0x16], false);
        let directed = aux_directed(OWN, central, adi, &[2, 1, 6]);
        assert_eq!(directed.as_bytes(), [
            0x47, 19, 0x4F, 0x0B, 1, 2, 3, 4, 5, 6, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0xBC, 0x0A, 2, 1, 6
        ]);
        // To a resolvable private address: RxAdd.
        let private = Peer::new([0xAA, 0xFB, 0x0D, 0x94, 0x81, 0x70], true);
        assert_eq!(aux_directed(OWN, private, adi, &[]).as_bytes()[..4], [0xC7, 16, 0x4F, 0x0B]);
        // From a public address: no TxAdd.
        assert_eq!(aux_undirected(central, adi, &[]).as_bytes()[..4], [0x07, 10, 0x49, 0x09]);
        assert_eq!(AUX_HEADER_LEN, 10);
        assert_eq!(AUX_DIRECTED_HEADER_LEN, 16);
    }

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn auxiliary_pdus_take_the_data_the_chip_sends_and_cut_off_the_rest() {
        // The nRF52832 sends 255 octets of payload: 245 of data, 239 when
        // directed. The nRF51's radio takes at most 254 octets of a packet
        // from RAM (nRF51 Series Reference Manual v3.0, 17.1.3): 252 of
        // payload, 242 and 236 of data.
        let (payload, undirected, directed) = if cfg!(feature = "nrf51") { (252, 242, 236) } else { (255, 245, 239) };
        assert_eq!(AUX_PAYLOAD_MAX, payload);
        assert!(HEADER_LEN + AUX_PAYLOAD_MAX <= chip::PACKET_RAM_MAX);
        let adi = Adi::new(0, 1);
        let central = Peer::new([0x11; 6], false);
        let data = [0xA5; 256];
        for len in [undirected, undirected + 1, 256] {
            let pdu = aux_undirected(OWN, adi, &data[..len]);
            assert_eq!(pdu.as_bytes().len(), HEADER_LEN + AUX_HEADER_LEN + undirected);
            assert_eq!(usize::from(pdu.as_bytes()[1]), payload);
            assert!(pdu.as_bytes()[HEADER_LEN + AUX_HEADER_LEN..].iter().all(|&octet| octet == 0xA5));
        }
        for len in [directed, directed + 1] {
            let pdu = aux_directed(OWN, central, adi, &data[..len]);
            assert_eq!(pdu.as_bytes().len(), HEADER_LEN + AUX_DIRECTED_HEADER_LEN + directed);
            assert_eq!(usize::from(pdu.as_bytes()[1]), payload);
        }
    }

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn the_connect_response_targets_the_initiator_and_can_be_retargeted() {
        let initiator = Peer::new([2; 6], true);
        // AUX_CONNECT_RSP, TxAdd and RxAdd, 14 octets; extended header length
        // 13 and AdvMode 0; flags AdvA and TargetA (Core, Vol 6, Part B,
        // 2.3.3.2).
        let mut response = aux_connect_rsp(OWN, Peer::new([0; 6], false));
        assert_eq!(response.as_bytes()[..4], [0x48, 14, 0x0D, 0x03]);
        retarget(&mut response, initiator);
        assert_eq!(response.as_bytes(), aux_connect_rsp(OWN, initiator).as_bytes());
        assert_eq!(response.as_bytes(), [0xC8, 14, 0x0D, 0x03, 1, 2, 3, 4, 5, 6, 2, 2, 2, 2, 2, 2]);
        retarget(&mut response, Peer::new([3; 6], false));
        assert_eq!(response.as_bytes(), [0x48, 14, 0x0D, 0x03, 1, 2, 3, 4, 5, 6, 3, 3, 3, 3, 3, 3]);
    }

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn an_aux_connect_req_parses_as_a_connect_ind_with_channel_selection_algorithm_2() {
        // ChSel is reserved in AUX_CONNECT_REQ: the connection takes channel
        // selection algorithm 2 whatever the bit holds.
        let mut bytes = connection_request(CONNECT_IND | TX_ADD_RANDOM | RX_ADD_RANDOM, OWN);
        let request = ConnectInd::parse_aux(&bytes, OWN).unwrap();
        assert!(request.csa2 && request.central() == Peer::new([2; 6], true));
        assert_eq!((request.interval, request.timeout, request.hop), (12, 600, 5));
        bytes[0] |= CH_SEL;
        assert!(ConnectInd::parse_aux(&bytes, OWN).unwrap().csa2);
        for len in 0..bytes.len() {
            assert!(ConnectInd::parse_aux(&bytes[..len], OWN).is_none());
        }
        // Only to our address with our address type, and only that PDU
        // type and length.
        assert!(ConnectInd::parse_aux(&bytes, Peer::new([1, 2, 3, 4, 5, 7], true)).is_none());
        assert!(ConnectInd::parse_aux(&bytes, Peer::new(OWN.address, false)).is_none());
        let mut other = bytes;
        other[0] = ADV_EXT_IND | TX_ADD_RANDOM | RX_ADD_RANDOM;
        assert!(ConnectInd::parse_aux(&other, OWN).is_none());
        other = bytes;
        other[1] = 35;
        assert!(ConnectInd::parse_aux(&other, OWN).is_none());
    }

    #[cfg(feature = "extended-advertising")]
    #[test]
    fn the_initiator_of_an_aux_connect_req_is_read_from_its_first_octets() {
        let mut pdu = [0_u8; 36];
        pdu[0] = 0x05 | TX_ADD_RANDOM | RX_ADD_RANDOM;
        pdu[1] = 34;
        pdu[2..8].copy_from_slice(&[1, 2, 3, 4, 5, 0x46]);
        assert!(aux_connect_initiator(&pdu) == Some(Peer::new([1, 2, 3, 4, 5, 0x46], true)));
        // A public initiator.
        pdu[0] = 0x05;
        assert!(aux_connect_initiator(&pdu) == Some(Peer::new([1, 2, 3, 4, 5, 0x46], false)));
        // Not a connection request: another type or length, or too short.
        pdu[0] = 0x03;
        assert!(aux_connect_initiator(&pdu).is_none());
        pdu[0] = 0x05;
        pdu[1] = 12;
        assert!(aux_connect_initiator(&pdu).is_none());
        pdu[1] = 34;
        assert!(aux_connect_initiator(&pdu[..7]).is_none());
        // The answer to it names it.
        let mut response = aux_connect_rsp(Peer::new([9; 6], true), Peer::new([0; 6], false));
        retarget(&mut response, aux_connect_initiator(&pdu).unwrap());
        assert_eq!(response.as_bytes()[0], AUX_CONNECT_RSP | TX_ADD_RANDOM);
        assert_eq!(response.as_bytes()[10..16], [1, 2, 3, 4, 5, 0x46]);
        // The whole buffer of a PDU, for the reception after it.
        let buffer = aux_connect_rsp(Peer::new([9; 6], true), Peer::new([0; 6], false)).into_buffer();
        assert_eq!(buffer.len(), HEADER_LEN + AUX_CONNECT_RSP_LEN);
        assert_eq!(buffer[..2], [AUX_CONNECT_RSP | TX_ADD_RANDOM, 14]);
    }
}
