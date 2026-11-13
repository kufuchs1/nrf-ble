//! Peripheral side of a connection: connection events, acknowledgement, link
//! encryption and the LL control procedures a central starts.

/// Async, single-use encryption response entropy.
mod entropy;

/// The control PDU queue and the two transmit slots.
mod transmit;

#[cfg(feature = "event-timing")]
use crate::clock::RESTART_EARLY_US;
use crate::{
    bytes::{le16, le16_bytes},
    channel::{Hopping, UsedChannels},
    chip,
    clock::{Clock, SETUP_US, reached},
    crypto::{self, CONFIG_LEN, SCRATCH_LEN},
    health,
    link::{
        ACL_MAX,
        AclOut,
        ConnectionParams,
        Event,
        LATENCY_HOLD_EVENTS,
        LATENCY_HOLD_START_US,
        LATENCY_HOLD_US,
        LENGTH_DEFAULT,
        LENGTH_MAX,
        LtkAnswer,
        ParamRange,
        QUERY_FEATURES,
        QUERY_PHY,
        QUERY_VERSION,
        Shared,
    },
    maintenance,
    pdu::{BUFFER_LEN, ConnectInd, LLID_MASK, Llid, NESN, SN, field, valid_channel_map, valid_connection_parameters},
    power_control::{DEFAULT_LEVEL, LEVELS_DBM, PowerControl},
    radio::{Phy, RX_READY_US, Radio, TURNAROUND_IN_ANSWER, Turnaround},
};
use core::{iter, mem};
use embassy_futures::select::{Either, select};
use entropy::Prefetch;
use transmit::Ring;

/// Largest payload of a queued PDU.
const CONTROL_PAYLOAD_MAX: usize = 27;
/// Data PDU header in RAM: header, length and the RFU byte the CCM needs.
const DATA_HEADER_LEN: usize = 3;
/// Size of a data PDU buffer with the longest payload and a MIC.
const DATA_BUFFER_LEN: usize = DATA_HEADER_LEN + ACL_MAX + MIC_LEN;
/// Error code: MIC failure.
const ERROR_MIC_FAILURE: u8 = 0x3D;
/// Error code: PIN or key missing.
const ERROR_KEY_MISSING: u8 = 0x06;
/// Error code: unsupported remote feature.
const ERROR_UNSUPPORTED_FEATURE: u8 = 0x1A;
/// Error code: invalid link layer parameters.
const ERROR_INVALID_PARAMETERS: u8 = 0x1E;
/// Error code: controller hardware failure.
const ERROR_HARDWARE_FAILURE: u8 = 0x03;
/// Error code: link layer response timeout.
const ERROR_RESPONSE_TIMEOUT: u8 = 0x22;
/// Status of a request that succeeded.
const STATUS_SUCCESS: u8 = 0x00;
/// Error code: PDU not allowed in the current procedure.
const ERROR_PDU_NOT_ALLOWED: u8 = 0x24;
/// Error code: instant passed.
const ERROR_INSTANT_PASSED: u8 = 0x28;
/// Error code: unsupported link layer parameter value.
const ERROR_UNSUPPORTED_VALUE: u8 = 0x20;
/// Error code: connection failed to be established, no packet from the
/// central within six connection events.
const ERROR_FAILED_TO_ESTABLISH: u8 = 0x3E;
/// Error: unacceptable connection parameters.
const ERROR_UNACCEPTABLE_PARAMETERS: u8 = 0x3B;
/// Time the host gets to answer a central's connection parameter request,
/// well within the central's procedure timeout.
const HOST_REPLY_US: u32 = 30_000_000;
/// Maximum time allowed for an encryption procedure.
const PROCEDURE_TIMEOUT_US: u32 = 40_000_000;
/// Supported link layer features.
///
/// LE encryption, the connection parameters request procedure, the extended
/// reject indication, the peripheral-initiated feature exchange and LE ping
/// (bits 0 to 4), the LE 2M PHY (bit 8) where the radio has it, channel
/// selection algorithm 2 (bit 14) and LE power control (bits 33 and 34).
pub const FEATURES: [u8; 8] = [
    0x1F | if cfg!(feature = "data-length") { FEATURE_DATA_LENGTH } else { 0 },
    if chip::PHY_2M { 0x41 } else { 0x40 },
    0,
    0,
    0x06,
    0,
    0,
    0,
];
/// Feature bit in the first octet: LE data packet length extension.
const FEATURE_DATA_LENGTH: u8 = 0x20;
/// Longest time on the air of a data PDU the specification allows.
const LENGTH_TIME_MAX: u16 = 17_040;
/// Length of a message integrity check.
const MIC_LEN: usize = 4;
/// Connection parameter change at an instant.
const OP_CONNECTION_UPDATE_IND: u8 = 0x00;
/// Channel map change at an instant.
const OP_CHANNEL_MAP_IND: u8 = 0x01;
/// Connection termination.
const OP_TERMINATE_IND: u8 = 0x02;
/// Encryption request.
const OP_ENC_REQ: u8 = 0x03;
/// Encryption response.
const OP_ENC_RSP: u8 = 0x04;
/// Start of encryption request.
const OP_START_ENC_REQ: u8 = 0x05;
/// Start of encryption response.
const OP_START_ENC_RSP: u8 = 0x06;
/// Answer to an unsupported control PDU.
const OP_UNKNOWN_RSP: u8 = 0x07;
/// Feature exchange request from the central.
const OP_FEATURE_REQ: u8 = 0x08;
/// Feature exchange response.
const OP_FEATURE_RSP: u8 = 0x09;
/// Version exchange.
const OP_VERSION_IND: u8 = 0x0C;
/// Request to pause encryption for a key refresh.
const OP_PAUSE_ENC_REQ: u8 = 0x0A;
/// Answer to [`OP_PAUSE_ENC_REQ`], from both sides.
const OP_PAUSE_ENC_RSP: u8 = 0x0B;
/// Rejection of a procedure.
const OP_REJECT_IND: u8 = 0x0D;
/// Request to change the transmit power, with the sender's.
const OP_POWER_CONTROL_REQ: u8 = 0x23;
/// Answer to [`OP_POWER_CONTROL_REQ`].
const OP_POWER_CONTROL_RSP: u8 = 0x24;
/// Report of a change of the own transmit power.
const OP_POWER_CHANGE_IND: u8 = 0x25;
/// Feature exchange started by the peripheral.
const OP_PERIPHERAL_FEATURE_REQ: u8 = 0x0E;
/// Connection parameter request, from either side.
const OP_CONNECTION_PARAM_REQ: u8 = 0x0F;
/// Answer to [`OP_CONNECTION_PARAM_REQ`].
const OP_CONNECTION_PARAM_RSP: u8 = 0x10;
/// Rejection of a procedure, naming its opcode.
const OP_REJECT_EXT_IND: u8 = 0x11;
/// Ping request.
const OP_PING_REQ: u8 = 0x12;
/// Ping response.
const OP_PING_RSP: u8 = 0x13;
/// Data length request.
const OP_LENGTH_REQ: u8 = 0x14;
/// Data length response.
const OP_LENGTH_RSP: u8 = 0x15;
/// PHY preferences, starting the PHY update procedure.
const OP_PHY_REQ: u8 = 0x16;
/// PHY preferences answering [`OP_PHY_REQ`].
const OP_PHY_RSP: u8 = 0x17;
/// PHY change at an instant.
const OP_PHY_UPDATE_IND: u8 = 0x18;
/// PHYs this side prefers for both directions: LE 2M where the radio has
/// it.
const PREFERRED_PHYS: u8 = if chip::PHY_2M { 0x02 } else { 0x01 };
/// Interval of the connection statistics log.
const REPORT_INTERVAL_US: u32 = 10_000_000;
/// No received anchor yet since the last report: no deviation, no widening.
const NO_DRIFT: (i32, u32) = (0, 0);
/// Header bit: more data follows.
const MD: u8 = 0x10;
/// Queued PDUs.
const QUEUE_LEN: usize = 4;
/// Radio ramp-up time.
const RAMP_UP_US: u32 = RX_READY_US;
/// Extra listening before the earliest expected packet.
const RX_MARGIN_US: u32 = 30;
/// Extra listening after the latest expected access address.
const RX_TAIL_US: u32 = 30;
/// Microseconds per 10 ms unit.
const UNIT_10MS_US: u32 = 10_000;
/// Microseconds per 1.25 ms unit.
const UNIT_1250_US: u32 = 1250;
/// Version exchange payload: Bluetooth 5.2, the first with LE power
/// control, no company, subversion 0.
const VERSION: [u8; 5] = [0x0B, 0xFF, 0xFF, 0x00, 0x00];
/// Fixed part of the window widening in microseconds.
const WIDENING_FIXED_US: u32 = 16;
/// Interframe space.
const T_IFS_US: u32 = 150;
/// Time left before the next event for processing the packets of this one.
const EVENT_GUARD_US: u32 = 500;
/// Received control PDUs held for processing after the event.
const RX_SLOTS: usize = 3;
/// Connection events whose first exchange is logged, from the first.
const TRACE_EVENTS: u16 = 8;
/// Control PDUs sent or acknowledged per event that the log shows.
const TRACE_CONTROLS: usize = 4;
/// How long after the END the answer to an acknowledgement waits every 16th
/// event with the `ifs-delay-test` feature: past the radio's start, about
/// 150 us after the END, and well before our shortest packet, an empty PDU,
/// ends about 230 us after it, by which the nRF51's turnaround must be set.
#[cfg(feature = "ifs-delay-test")]
const IFS_DELAY_TEST_US: u32 = 160;
/// Time preparing the next PDU again may take, copy and sealing included,
/// after the host woke the sleep before an event, on top of [`SETUP_US`].
const PREPARE_AGAIN_US: u32 = 200;
/// Time that has to remain until the radio's start for preparing the next
/// PDU once TIMER0 restarted for the event, where the chip does
/// ([`chip::PREPARE_AFTER_RESTART`]): the preparation, 100 us, and the
/// radio's setup after it, 100 us. TIMER0 restarts [`SETUP_US`] before the
/// start, so a crystal that comes up more than about 100 us after the
/// restart leaves the data for the next event.
const PREPARE_LATE_US: u32 = 200;
// A crystal up to 70 us late still leaves the time.
const _: () =
    assert!(SETUP_US >= PREPARE_LATE_US.saturating_add(70), "a crystal up to 70 us late no longer leaves the time");
/// Highest transmit power in dBm.
const MAX_POWER_DBM: i8 = LEVELS_DBM.last().copied().unwrap_or(0);
/// Acceptable power reduction when no packet has been measured yet.
const UNKNOWN_REDUCTION: u8 = 0xFF;
/// Error code: different transaction collision, another procedure with an
/// instant runs.
const ERROR_DIFFERENT_TRANSACTION: u8 = 0x2A;
/// Offset field of a connection parameter request without a preference.
const NO_OFFSET: [u8; 2] = [0xFF, 0xFF];

/// Why a connection ended.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Ended {
    /// A controller error ended the link immediately.
    Error(u8),
    /// The host terminated the connection with this error code.
    Local(u8),
    /// The supervision timeout expired.
    Lost,
    /// The host reset the controller; no disconnection event is emitted.
    Reset,
    /// The central terminated the connection with this error code.
    Terminated(u8),
}

/// Counters of a connection.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct Stats {
    /// Our PDUs the central acknowledged.
    pub acked:             u32,
    /// Of [`Self::acked`], those with a payload.
    pub acked_data:        u32,
    /// Longest time from the END of a received packet until the answer to
    /// an acknowledgement was in place, in microseconds.
    pub answer_ack_us_max: u32,
    /// Longest time from the END of a received packet until the answer was
    /// in place, in microseconds: the radio reads it about 140 us after the
    /// END on the nRF51.
    pub answer_us_max:     u32,
    /// Packets received with a CRC error.
    pub crc_errors:        u32,
    /// Connection events.
    pub events:            u32,
    /// Acknowledgements answered with an empty PDU although more of ours
    /// waited, as nothing was prepared: a second acknowledgement in one
    /// event where only one PDU is prepared per event.
    pub fallback:          u32,
    /// Answers to an acknowledgement in place only after the radio started
    /// sending: it sent our previous PDU again, with its previous flags.
    pub late_ack:          u32,
    /// Answers without an acknowledgement in place only after the radio
    /// started sending: our PDU went out with its previous flags.
    pub late_noack:        u32,
    /// Connection events without a packet from the central.
    pub missed:            u32,
    /// Longest preparation of the next PDU between events, copy and
    /// sealing, in microseconds.
    pub prepare_us_max:    u32,
    /// New data PDUs received.
    pub received:          u32,
    /// Packets the central sent again that we had taken: it missed our
    /// answer, or our answer came late. A packet refused for lack of room
    /// comes again as a new one and is not counted.
    pub retx:              u32,
    /// Of [`Self::retx`], those that acknowledged our PDU: the central heard
    /// an answer of ours that did not acknowledge its packet. Each late
    /// answer without an acknowledgement to a packet we took is followed by
    /// one, as the radio sent our PDU with its previous flags (see
    /// [`Self::late_noack`]); only a count beyond `late_noack` points to an
    /// answer the central did not take, such as an echo of its packet.
    pub retx_with_ack:     u32,
    /// Longest time from TIMER0's restart before an event, [`SETUP_US`]
    /// ahead of the radio's start, until that start was programmed, in
    /// microseconds: a late crystal or restart and the radio's setup, and on
    /// the nRF52832 the preparation of data the host queued while the crystal
    /// started. What it leaves of `SETUP_US` bounds what may still run after
    /// the restart, such as that preparation on the nRF51.
    pub setup_us_max:      u32,
    /// Connection events skipped with peripheral latency.
    pub skipped:           u32,
}

impl Stats {
    /// Logs the counters of the interframe space answers, after `label`.
    #[cfg(feature = "defmt")]
    #[inline]
    pub fn log_answers(&self, label: &str) {
        info!(
            "{=str}: {} retx ({} with ack), {} acked ({} data), {} late ({} on ack), answer max {} us (ack {} us), {} fallback, prepare max {} us, setup max {} us",
            label,
            self.retx,
            self.retx_with_ack,
            self.acked,
            self.acked_data,
            self.late_ack.wrapping_add(self.late_noack),
            self.late_ack,
            self.answer_us_max,
            self.answer_ack_us_max,
            self.fallback,
            self.prepare_us_max,
            self.setup_us_max
        );
    }
}

/// The central's encryption request as the host looks up the key by it.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
struct KeyLookup {
    /// Central encrypted diversifier.
    ediv: [u8; 2],
    /// Central random number.
    rand: [u8; 8],
}

/// State of the encryption start procedure.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
enum Phase {
    /// A validated request waits for its prefetched, single-use random block.
    AwaitingEntropy(KeyLookup),
    /// The host is asked for the long term key, and whether the key request
    /// event reached it yet.
    AwaitingKey(KeyLookup, bool),
    /// Our encrypted pause response was sent; the central's plain one is
    /// expected.
    AwaitingPauseResponse,
    /// The start request was sent and the peer must authenticate its reply.
    AwaitingStartResponse,
    /// No procedure running.
    Idle,
    /// Encryption is paused both ways; the central starts it again with the
    /// new key.
    Paused,
    /// Our pause response is queued, still encrypted.
    Pausing,
    /// Encryption is being started.
    Starting,
}

/// A procedure this side starts once.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Request {
    /// Asked, or answered or refused by the central: nothing more to do.
    Done,
    /// Not asked yet.
    NotStarted,
    /// Asked; the central answers until the deadline.
    Requested(u32),
}

/// Kind of encryption start.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Procedure {
    /// The first start of the connection.
    First,
    /// A key refresh after a pause.
    Refresh,
}

/// Link encryption state.
struct Encryption {
    /// IV of the session.
    iv:         [u8; 8],
    /// State of the start procedure.
    phase:      Phase,
    /// Whether the start is the first or refreshes the key.
    procedure:  Procedure,
    /// CCM configuration for received packets.
    rx_config:  [u8; CONFIG_LEN],
    /// Packet counter of the next new received packet.
    rx_counter: u64,
    /// Whether received packets are encrypted.
    rx_on:      bool,
    /// CCM scratch area.
    scratch:    [u8; SCRATCH_LEN],
    /// Session key diversifier.
    skd:        [u8; 16],
    /// CCM configuration for sent packets.
    tx_config:  [u8; CONFIG_LEN],
    /// Packet counter of the next new sent packet.
    tx_counter: u64,
    /// Whether sent packets are encrypted, from the next PDU prepared.
    tx_on:      bool,
}

impl Encryption {
    /// Forgets the keys, the IVs and the session key diversifier of the
    /// link.
    fn wipe(&mut self) {
        crypto::wipe(&mut self.iv);
        crypto::wipe(&mut self.rx_config);
        crypto::wipe(&mut self.scratch);
        crypto::wipe(&mut self.skd);
        crypto::wipe(&mut self.tx_config);
    }
}

/// Where the next packet from the central is expected.
#[derive(Clone, Copy)]
enum Expect {
    /// At the anchor `interval` after the last one.
    Anchor,
    /// Within a transmit window: start time of the first packet, and size.
    Window {
        /// Earliest packet start.
        start: u32,
        /// Window length.
        size:  u32,
    },
}

/// Data length extension (Core, Vol 6, Part B, 4.5.10): the longest payload
/// in octets and its time on the air in microseconds, each way.
#[derive(Clone, Copy)]
struct DataLength {
    /// What the central knows this side may send: the defaults until an
    /// `LL_LENGTH_RSP` of ours was acknowledged or the central answered our
    /// `LL_LENGTH_REQ`. Longer packets than announced are never sent.
    announced_tx: [u16; 2],
    /// What the host lets this side send.
    local_tx:     [u16; 2],
    /// What this side offered in its last `LL_LENGTH_REQ` or `LL_LENGTH_RSP`,
    /// until the central took it.
    offered_tx:   Option<[u16; 2]>,
    /// What the central receives, as it said.
    peer_rx:      [u16; 2],
    /// What the central sends, as it said.
    peer_tx:      [u16; 2],
    /// Effective values last reported to the host: transmit octets and
    /// time, receive octets and time.
    reported:     [u16; 4],
    /// Whether the central answered our `LL_LENGTH_REQ` as unknown.
    unsupported:  bool,
}

impl DataLength {
    /// Effective transmit octets and time and receive octets and time.
    const fn effective(&self) -> [u16; 4] {
        let [default_octets, default_time] = LENGTH_DEFAULT;
        let [max_octets, max_time] = LENGTH_MAX;
        // A host that lowers its length takes effect at once: shorter packets
        // are always allowed.
        [
            self.local_tx[0].min(self.announced_tx[0]).min(self.peer_rx[0]),
            self.local_tx[1].min(self.announced_tx[1]).min(self.peer_rx[1]).max(default_time),
            max_octets.min(self.peer_tx[0]).max(default_octets),
            max_time.min(self.peer_tx[1]).max(default_time),
        ]
    }

    /// The defaults until the procedure ran, with what the host lets this
    /// side send.
    const fn new(local_tx: [u16; 2]) -> Self {
        let [octets, time] = LENGTH_DEFAULT;
        Self {
            announced_tx: LENGTH_DEFAULT,
            local_tx,
            offered_tx: None,
            peer_rx: LENGTH_DEFAULT,
            peer_tx: LENGTH_DEFAULT,
            reported: [octets, time, octets, time],
            unsupported: false,
        }
    }

    /// Makes the values this side offered effective: the central answered
    /// our request, or acknowledged our response.
    const fn offer_taken(&mut self) {
        if let Some(offered) = self.offered_tx.take() {
            self.announced_tx = offered;
        }
    }

    /// The payload of `LL_LENGTH_REQ` and `LL_LENGTH_RSP`: the longest
    /// supported reception and what this side may send, which becomes
    /// effective once the central took it.
    fn pdu(&mut self, code: u8) -> [u8; 9] {
        self.offered_tx = Some(self.local_tx);
        let mut pdu = [code, 0, 0, 0, 0, 0, 0, 0, 0];
        let [max_octets, max_time] = LENGTH_MAX;
        let values = [max_octets, max_time, self.local_tx[0], self.local_tx[1]];
        for (target, source) in pdu.iter_mut().skip(1).zip(values.iter().flat_map(|&value| le16_bytes(value))) {
            *target = source;
        }
        pdu
    }

    /// Takes the central's values from its `LL_LENGTH_REQ` or `LL_LENGTH_RSP`,
    /// within the specification's range.
    fn take_peer(&mut self, params: &[u8]) {
        let Some(bytes) = field::<8>(params, 0) else { return };
        let mut values: [u16; 4] = [0; 4];
        let (pairs, _) = bytes.as_chunks::<2>();
        for (value, &pair) in values.iter_mut().zip(pairs) {
            *value = le16(pair);
        }
        let [rx_octets, rx_time, tx_octets, tx_time] = values;
        let [default_octets, default_time] = LENGTH_DEFAULT;
        let octets = |value: u16| value.clamp(default_octets, LENGTH_MAX[0]);
        let time = |value: u16| value.clamp(default_time, LENGTH_TIME_MAX);
        self.peer_rx = [octets(rx_octets), time(rx_time)];
        self.peer_tx = [octets(tx_octets), time(tx_time)];
    }
}

/// A central's connection parameter request waiting for an answer.
#[derive(Clone, Copy)]
struct RemoteRequest {
    /// Whether the host was asked, and until when it may answer.
    asked:  Option<u32>,
    /// The request's parameters, whose offsets the response repeats.
    params: [u8; 23],
}

/// A PDU of ours the central acknowledged, as the answer within the
/// interframe space saw it.
#[derive(Clone, Copy)]
struct Acked {
    /// Its kind.
    kind:   TxKind,
    /// Its first payload octet: the opcode of a control PDU.
    opcode: u8,
}

/// The answer to a packet from the central, as decided within the
/// interframe space, for the work after it.
#[derive(Clone, Copy)]
struct Decision {
    /// Our PDU the packet acknowledged, if it did.
    acked:     Option<Acked>,
    /// The central's header, if the packet had a valid CRC.
    central:   Option<u8>,
    /// Whether the packet was one the central sent before.
    duplicate: bool,
    /// Whether the acknowledgement was answered with an empty PDU although
    /// more of ours waited.
    fallback:  bool,
    /// What follows the answer.
    follow:    Follow,
    /// Whether the packet left our PDU unacknowledged on a link that
    /// already received, which counts as a loss for the power control.
    nacked:    bool,
}

/// What follows an answer within the interframe space.
#[derive(Clone, Copy)]
struct Follow {
    /// The MD flag of the answer.
    md:   bool,
    /// Whether the event goes on after the answer.
    more: bool,
}

/// The acknowledgement scheme of the link (Core, Vol 6, Part B, 4.5.9),
/// as the interframe space reads it.
#[derive(Clone, Copy)]
struct Sequence {
    /// Next expected sequence number.
    nesn:     bool = false,
    /// Whether the received PDU is new and has to be processed.
    received: bool = false,
    /// Sequence number of the PDU on the air.
    sn:       bool = false,
}

/// Largest times since the last report, in microseconds.
#[derive(Clone, Copy, Default)]
struct Peaks {
    /// Answer in place after the END.
    answer:     u32,
    /// Answer to an acknowledgement in place after the END.
    answer_ack: u32,
    /// Preparation of the next PDU.
    prepare:    u32,
}

/// Room for new packets from the central, counted before the event, so the
/// answer need not ask the host.
#[derive(Clone, Copy)]
struct Room {
    /// Data PDUs the host can take: none while it waits for the link's
    /// start.
    acl:     u8,
    /// Control PDUs that can wait for processing after the event.
    control: u8,
}

/// A received PDU in plain text, waiting to be processed.
#[derive(Clone, Copy)]
struct Pending {
    /// Header and payload.
    bytes:     [u8; DATA_HEADER_LEN + CONTROL_PAYLOAD_MAX],
    /// Whether it came encrypted.
    encrypted: bool,
}

/// A PDU waiting to be sent.
#[derive(Clone, Copy)]
struct Queued {
    /// Payload.
    data: [u8; CONTROL_PAYLOAD_MAX],
    /// Payload length.
    len:  u8,
    /// Logical link identifier.
    llid: Llid,
}

/// Kind of the PDU being sent.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
enum TxKind {
    /// The last fragment of ACL data from the host.
    Acl,
    /// A fragment of ACL data from the host with more to follow.
    AclPart,
    /// LL control PDU.
    Control,
    /// Empty PDU.
    Empty,
    /// Termination requested by the host.
    Terminate,
}

/// A data PDU in RAM as the radio and the CCM read it: header, length, the
/// S1 byte, payload and MIC. Word aligned, so that its copies move words.
#[derive(Clone, Copy)]
#[repr(C, align(4))]
struct Packet([u8; DATA_BUFFER_LEN]);

/// Where a prepared PDU comes from, which committing it takes it from.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Source {
    /// A fragment of the host's packet in [`Connection::acl`], ending at
    /// octet `end`, the packet's last if `last`.
    Acl {
        /// Octets of the packet sent with this fragment.
        end:  u8,
        /// Whether the fragment ends the packet.
        last: bool,
    },
    /// Nothing: an empty PDU.
    Empty,
    /// The first PDU of the control queue.
    Queue,
}

/// A PDU to send, in plain text and, on an encrypted link, sealed.
#[derive(Clone, Copy)]
struct TxSlot {
    /// Whether [`Self::sealed`] goes on the air: set when it is prepared, so
    /// a retransmission keeps the packet counter it was given, or stays
    /// plain.
    encrypted: bool,
    /// Kind of the PDU.
    kind:      TxKind,
    /// The PDU in plain text; the header flags are patched here when it
    /// goes out plain.
    plain:     Packet,
    /// The PDU as the CCM sealed it; the header flags are patched here when
    /// it goes out encrypted.
    sealed:    Packet,
    /// Where it comes from.
    source:    Source,
}

/// Control PDUs this side committed or the central acknowledged in an
/// event, and the first exchange of the event, kept for the log after it.
#[derive(Clone, Copy, Default)]
struct Trace {
    /// Opcodes of control PDUs committed (`true`) or acknowledged
    /// (`false`), in order.
    controls: [(bool, u8); TRACE_CONTROLS],
    /// Number of entries in [`Self::controls`].
    count:    u8,
    /// The first exchange: the central's header, ours, and whether ours
    /// came too late.
    first:    Option<(u8, u8, bool)>,
}

/// Connection parameters taking effect at an instant.
#[derive(Clone, Copy)]
struct Update {
    /// Event counter at which they take effect.
    instant:    u16,
    /// New interval in microseconds.
    interval:   u32,
    /// New peripheral latency in events.
    latency:    u16,
    /// New parameters in link layer units.
    params:     ConnectionParams,
    /// Whether the update answers a request of the host, which then learns
    /// of it even without a change.
    requested:  bool,
    /// New supervision timeout in microseconds.
    timeout:    u32,
    /// Transmit window offset in microseconds.
    win_offset: u32,
    /// Transmit window size in microseconds.
    win_size:   u32,
}

/// An established connection.
pub struct Connection {
    /// Fatal controller error; no further packets may be sent.
    abort:                  Option<u8> = None,
    /// The host's ACL packet being sent in fragments, and its octets sent.
    acl:                    Option<(AclOut, u8)>,
    /// Access address time of the last received packet.
    anchor:                 u32,
    /// Event counter of [`Self::anchor`].
    anchor_counter:         u16 = 0,
    /// Transmit power level the central last learned.
    announced_power:        [usize; 2],
    /// The central's features, once known.
    central_features:       Option<[u8; 8]>,
    /// Channel map update and its instant.
    channel_update:         Option<(UsedChannels, u16)>,
    /// ACL packets acknowledged and not yet reported to the host.
    completed:              u16 = 0,
    /// Counter of the next connection event.
    counter:                u16 = 0,
    /// Which slot holds the PDU on the air: the second if set.
    cur:                    bool = false,
    /// Largest deviation of a received anchor from its expected time since
    /// the last report, and the window widening it was received with, in
    /// microseconds.
    drift:                  (i32, u32),
    /// Link encryption.
    encryption:             Encryption,
    /// Security notification retained until the host event queue has room.
    encryption_change:      Option<(u8, bool)>,
    /// Deadline for accepting the first packet of a new connection.
    establishment_deadline: Option<u32>,
    /// Air time of another exchange after an answer, at the current
    /// lengths, computed before the event.
    exchange_budget_us:     u32 = 0,
    /// Where the next packet is expected.
    expect:                 Expect,
    /// Rejected feature query awaiting host notification.
    feature_error:          Option<u8> = None,
    /// The feature exchange this side starts.
    features_request:       Request = Request::NotStarted,
    /// Until when no connection event is skipped: the first second of the
    /// link, and a while after each PDU with a payload either way.
    hold_until:             Option<u32>,
    /// Channel selection.
    hopping:                Hopping,
    /// PHY preferences requested by the host until completion.
    host_phy:               Option<[u8; 2]>,
    /// Host queries pending completion.
    host_queries:           u8 = 0,
    /// Connection interval in microseconds.
    interval:               u32,
    /// Time the last valid packet was received.
    last_valid:             u32,
    /// Whether our last answer was in place only after the radio started
    /// sending it: a missing acknowledgement that follows is ours.
    late_answer:            bool = false,
    /// Peripheral latency in events.
    latency:                u16,
    /// Data length extension state.
    length:                 DataLength,
    /// The data length procedure this side starts.
    length_request:         Request = Request::NotStarted,
    /// Used data channels.
    map:                    UsedChannels,
    /// Status for the connection parameter requests that were part of the
    /// host's answer, once the central's request ended without an update.
    merged_outcome:         Option<u8> = None,
    /// Whether the free slot holds a prepared PDU to send next.
    next_ready:             bool = false,
    /// Transmit PHY to apply with the next PHY instant.
    next_tx_phy:            Phy = Phy::M1,
    /// Ordered host notifications retained while its queue is full.
    notifications:          [Option<Event>; 3],
    /// Deadline of the host's connection parameter request, while it runs.
    param_request:          Option<u32> = None,
    /// Status of the host's connection parameter request to report when it
    /// ended without an update: a failure, or success for parameters already
    /// in place.
    param_status:           Option<u8> = None,
    /// Pending connection parameter update.
    param_update:           Option<Update>,
    /// Time of the last packet with a valid MIC, once encrypted, and
    /// whether a ping asked for one since.
    payload_timer:          Option<(u32, bool)>,
    /// Largest answer and preparation times since the last report.
    peaks:                  Peaks,
    /// Received packets with a payload, in order, waiting for processing
    /// after the event.
    pending:                Ring<Pending, RX_SLOTS>,
    /// PHY both ways.
    phy:                    Phy = Phy::M1,
    /// The PHY update this side asks for.
    phy_request:            Request = Request::NotStarted,
    /// PHY procedure completion awaiting notification.
    phy_status:             Option<u8> = None,
    /// PHY change and its instant.
    phy_update:             Option<(Phy, u16)>,
    /// Response deadline of our `LL_PING_REQ` (Core, Vol 6, Part B, 5.2).
    ping_request:           Option<u32> = None,
    /// Transmit power control.
    power:                  [PowerControl; 2],
    /// PHY mask for which the peer has requested power control.
    power_reporting:        u8 = 0,
    /// PHY preference for this connection.
    preferred_phys:         [u8; 2],
    /// Deadline of the current encryption procedure, if any.
    procedure_deadline:     Option<u32> = None,
    /// PDUs waiting to be sent.
    queue:                  Ring<Queued, QUEUE_LEN>,
    /// A central's connection parameter request waiting for an answer.
    remote_request:         Option<RemoteRequest>,
    /// Deadline of the central's connection parameter request we answered,
    /// until its `LL_CONNECTION_UPDATE_IND` or rejection.
    remote_update:          Option<u32> = None,
    /// Time of the next statistics log.
    report_at:              u32,
    /// Counters and crystal restarts at the last statistics log.
    reported:               (Stats, u32),
    /// Room for new packets from the central in the coming event.
    room:                   Room,
    /// Decrypted received PDU.
    rx_plain:               [u8; BUFFER_LEN],
    /// Sum of both sleep clock accuracies in ppm.
    sca_ppm:                u32,
    /// The sequence numbers both ways, and whether the received PDU is new.
    seq:                    Sequence,
    /// Events skipped in a row.
    skipped:                u16 = 0,
    /// The PDU on the air until acknowledged, in the second slot if set,
    /// and the next one prepared in the other.
    slots:                  (TxSlot, TxSlot),
    /// Counters.
    stats:                  Stats,
    /// Termination requested by the host, and whether it was acknowledged.
    terminate:              Option<(u8, bool)>,
    /// Local termination cannot be prolonged by incoming keepalive packets.
    terminate_deadline:     Option<u32> = None,
    /// Termination received from the central.
    terminated:             Option<u8> = None,
    /// Supervision timeout in microseconds.
    timeout:                u32,
    /// Control PDUs and the first exchange of the event, for the log.
    trace:                  Trace,
    /// Kind of the PDU on the air.
    tx_kind:                TxKind = TxKind::Empty,
    /// Transmit PHY, independent of the receive PHY.
    tx_phy:                 Phy = Phy::M1,
    /// Parameter update events still owed to the host beyond
    /// the retained notifications, with their status and parameters.
    updates_owed:           (u8, u8, ConnectionParams),
    /// Remote version, retained once our only version response is queued.
    version:                Option<[u8; 5]>,
    /// Version procedure state, including its response deadline.
    version_request:        Request = Request::NotStarted,
}

impl Connection {
    /// Takes the acknowledgement of our PDU, within the interframe space:
    /// sends the prepared PDU next, or an empty one if none is prepared. A
    /// retransmission of the central acknowledges too (Core, Vol 6, Part B,
    /// 4.5.9). Returns what was acknowledged and whether the empty PDU stands
    /// in for more that waits.
    const fn ack_fast(&mut self, header: u8) -> (Option<Acked>, bool) {
        if (header & NESN != 0) == self.seq.sn {
            return (None, false);
        }
        self.seq.sn = !self.seq.sn;
        let acked = Acked {
            kind:   self.tx_kind,
            opcode: self.current().plain.0.get(DATA_HEADER_LEN).copied().unwrap_or_default(),
        };
        if self.next_ready {
            self.commit_next();
            return (Some(acked), false);
        }
        let waits = !self.queue.is_empty() || (self.acl.is_some() && self.encryption.phase == Phase::Idle);
        self.commit_empty();
        (Some(acked), waits)
    }

    /// What an acknowledgement of our PDU completes, after the answer: the
    /// host's packet, a termination or a length response, and the hold of
    /// the latency after a payload.
    const fn after_ack(&mut self, acked: Acked) {
        self.stats.acked = self.stats.acked.wrapping_add(1);
        if acked.kind != TxKind::Empty {
            self.stats.acked_data = self.stats.acked_data.wrapping_add(1);
            self.hold_latency_from(self.last_valid);
        }
        match acked.kind {
            TxKind::Acl => self.completed = self.completed.saturating_add(1),
            TxKind::Terminate => {
                if let Some((reason, false)) = self.terminate {
                    self.terminate = Some((reason, true));
                }
            },
            TxKind::Control if acked.opcode == OP_LENGTH_RSP => self.length.offer_taken(),
            TxKind::AclPart | TxKind::Control | TxKind::Empty => {},
        }
        if matches!(acked.kind, TxKind::Control | TxKind::Terminate) {
            self.trace.control(false, acked.opcode);
        }
    }

    /// The work of an answer once it is in place: the signal strength, the
    /// received packet for the host or for after the event, what an
    /// acknowledgement completes, a loss for the power control, and the
    /// counters. `answer_us` is how long after the END the answer was in
    /// place, and `late` whether the radio had started sending before.
    fn after_answer(
        &mut self,
        decision: Decision,
        rx: &[u8; BUFFER_LEN],
        (signal, late, answer_us): (Option<u8>, bool, u32),
        shared: &Shared,
    ) {
        if decision.central.is_some()
            && let Some(rssi) = signal
        {
            for_phy_mut(&mut self.power, self.tx_phy).on_packet(rssi);
        }
        if self.seq.received {
            self.stash(rx, self.encryption.rx_on, shared);
        }
        if let Some(acked) = decision.acked {
            self.after_ack(acked);
            if matches!(self.tx_kind, TxKind::Control | TxKind::Terminate) {
                let opcode = self.current().plain.0.get(DATA_HEADER_LEN).copied().unwrap_or_default();
                self.trace.control(true, opcode);
            }
        } else if decision.nacked && !self.late_answer {
            // The central did not hear our last packet, unless it came too
            // late: then the radio resent the one before, and the loss is
            // ours, not the path's.
            for_phy_mut(&mut self.power, self.tx_phy).on_loss();
        } else {
            // Nothing acknowledged, nothing lost.
        }
        self.late_answer = late;
        let acked = decision.acked.is_some();
        if late {
            if acked {
                self.stats.late_ack = self.stats.late_ack.wrapping_add(1);
            } else {
                self.stats.late_noack = self.stats.late_noack.wrapping_add(1);
            }
        }
        self.peaks.answer = self.peaks.answer.max(answer_us);
        self.stats.answer_us_max = self.stats.answer_us_max.max(answer_us);
        if acked {
            self.peaks.answer_ack = self.peaks.answer_ack.max(answer_us);
            self.stats.answer_ack_us_max = self.stats.answer_ack_us_max.max(answer_us);
        }
        if decision.duplicate {
            self.stats.retx = self.stats.retx.wrapping_add(1);
            if acked {
                self.stats.retx_with_ack = self.stats.retx_with_ack.wrapping_add(1);
            }
        }
        if decision.fallback {
            self.stats.fallback = self.stats.fallback.wrapping_add(1);
        }
        if self.counter < TRACE_EVENTS
            && self.trace.first.is_none()
            && let Some(central) = decision.central
        {
            let ours = self.current().plain.0.first().copied().unwrap_or_default();
            let flags = if self.seq.sn { SN } else { 0 }
                | if self.seq.nesn { NESN } else { 0 }
                | if decision.follow.md { MD } else { 0 };
            self.trace.first = Some((central, (ours & LLID_MASK) | flags, late));
        }
    }

    /// Tells a central that supports power control about a change of the
    /// own transmit power.
    const fn announce_power(&mut self) {
        let level = for_phy_mut(&mut self.power, self.tx_phy).level();
        let supports = self.central_features.is_some_and(const |[_, _, _, _, power, ..]| power & 0x02 != 0);
        let free = self.encryption.phase == Phase::Idle && self.queue.is_empty();
        if level == *for_phy_mut(&mut self.announced_power, self.tx_phy)
            || !supports
            || !free
            || self.power_reporting & self.tx_phy.hci() == 0
        {
            return;
        }
        let before = i32::from(tx_power(*for_phy_mut(&mut self.announced_power, self.tx_phy)));
        let now = tx_power(level);
        let delta = i8::try_from(i32::from(now).saturating_sub(before)).unwrap_or_default();
        self.enqueue(Llid::Control, &[
            OP_POWER_CHANGE_IND,
            self.tx_phy.hci(),
            limit_flags(level),
            delta.cast_unsigned(),
            now.cast_unsigned(),
        ]);
        *for_phy_mut(&mut self.announced_power, self.tx_phy) = level;
    }

    /// Patches the header flags of the PDU on the air and returns the
    /// buffer the radio sends: the only write within the interframe space
    /// to a buffer the radio may already read, one byte, whose old or new
    /// value are both a valid answer.
    const fn answer_buffer(&mut self, md: bool) -> *mut u8 {
        let flags = if self.seq.sn { SN } else { 0 } | if self.seq.nesn { NESN } else { 0 } | if md { MD } else { 0 };
        let buffer = &mut self.current_mut().on_air().0;
        if let Some(header) = buffer.first_mut() {
            *header = (*header & LLID_MASK) | flags;
        }
        buffer.as_mut_ptr()
    }

    /// Applies parameter and channel map updates due at the current event.
    #[inline(never)]
    fn apply_instants(&mut self, shared: &Shared) {
        if let Some((map, instant)) = self.channel_update
            && instant == self.counter
        {
            self.map = map;
            self.channel_update = None;
            info!("channel map updated");
        }
        if let Some((phy, instant)) = self.phy_update
            && instant == self.counter
        {
            self.phy = phy;
            self.tx_phy = self.next_tx_phy;
            shared.set_phys(self.phy.hci(), self.tx_phy.hci());
            self.host_phy = None;
            shared.complete_query(QUERY_PHY);
            self.phy_update = None;
            self.notify(Event::PhyUpdated { rx: phy.hci(), status: STATUS_SUCCESS, tx: self.tx_phy.hci() }, shared);
            info!("PHY now {}M", phy.hci());
        }
        if let Some(update) = self.param_update
            && update.instant == self.counter
        {
            let old_anchor = self.expected_anchor();
            self.expect = Expect::Window {
                start: old_anchor.wrapping_sub(self.phy.address_offset_us()).wrapping_add(update.win_offset),
                size:  update.win_size,
            };
            let changed =
                self.interval != update.interval || self.latency != update.latency || self.timeout != update.timeout;
            self.interval = update.interval;
            self.latency = update.latency;
            self.timeout = update.timeout;
            self.param_update = None;
            // The host learns of updates that change something or that it
            // asked for (Core, Vol 6, Part B, 5.1.1), once per LE Connection
            // Update it sent: its own request, and those that were part of
            // its answer to the central's request this update ends.
            let owed = u8::from(update.requested).saturating_add(shared.take_merged_updates());
            self.complete_updates(owed.max(u8::from(changed)), STATUS_SUCCESS, update.params, shared);
            if update.requested {
                shared.finish_param_request();
            }
            info!("connection interval now {} us", update.interval);
        }
    }

    /// Prepares the decryption of the next received packet, if the link is
    /// encrypted. Returns false and ends the link if the counter ran out.
    fn arm_decryption(&mut self, rx: &mut [u8; BUFFER_LEN]) -> bool {
        if !self.encryption.rx_on {
            return true;
        }
        if !crypto::set_counter(&mut self.encryption.rx_config, self.encryption.rx_counter) {
            self.abort = Some(ERROR_MIC_FAILURE);
            return false;
        }
        let pointers = (rx.as_mut_ptr(), self.rx_plain.as_mut_ptr());
        let scratch = &mut self.encryption.scratch;
        // SAFETY: the configuration, scratch and both buffers live in this
        // connection or are borrowed for the exchange, which ends the
        // decryption with `wait_decrypted`, `stop` or `disarm`.
        let () = unsafe { crypto::arm_decrypt(&self.encryption.rx_config, pointers, scratch, self.phy) };
        true
    }

    /// Whether the current event can pass without listening: nothing to send
    /// or acknowledge and no procedure running. As in Zephyr, latency also
    /// stops while a connection or PHY update waits for its instant, so the
    /// anchor is fresh when the timing or the PHY changes. It stops too
    /// while the latency is held: in the first second of the link, a while
    /// after traffic, and while the host holds it, so that a central's
    /// request is answered at the next event.
    fn can_skip(&self, now: u32, shared: &Shared) -> bool {
        self.hold_until.is_none_or(|until| reached(now, until))
            && !shared.latency_held()
            && matches!(self.expect, Expect::Anchor)
            && self.param_update.is_none()
            && self.phy_update.is_none()
            && self.tx_kind == TxKind::Empty
            && self.acl.is_none()
            && self.queue.is_empty()
            && self.terminate.is_none()
            && self.encryption.phase == Phase::Idle
            && self.encryption_change.is_none()
            && self.notifications.iter().all(Option::is_none)
            && !shared.has_acl_out()
    }

    /// Keeps authenticated packets coming (LE Ping): pings the central when
    /// three quarters of the authenticated payload timeout passed without a
    /// packet with a valid MIC, and tells the host when all of it passed.
    fn check_payload(&mut self, now: u32, shared: &Shared) {
        let Some((last, pinged)) = self.payload_timer else { return };
        let timeout = shared.payload_timeout();
        let elapsed = now.wrapping_sub(last);
        if elapsed >= timeout {
            // Retained until the host takes it, once.
            if !self.notifications.contains(&Some(Event::PayloadTimeout)) {
                self.notify(Event::PayloadTimeout, shared);
            }
            self.payload_timer = Some((now, false));
            info!("authenticated payload timeout expired");
        } else if !pinged
            && self.ping_request.is_none()
            && elapsed >= timeout.saturating_sub(timeout.wrapping_shr(2))
            && self.encryption.phase == Phase::Idle
            && self.queue.is_empty()
        {
            self.enqueue(Llid::Control, &[OP_PING_REQ]);
            self.payload_timer = Some((last, true));
            self.ping_request = Some(now.wrapping_add(PROCEDURE_TIMEOUT_US));
        } else {
            // Authenticated traffic is recent enough.
        }
    }

    /// Validates a packet with a valid CRC within the interframe space and
    /// takes a new one if there is room: its NESN is processed apart, by
    /// [`Self::ack_fast`], also for a retransmission. Duplicate payloads use
    /// the previous CCM counter and must not be delivered or consume another
    /// nonce, as in the Core receive sequence and Zephyr. Returns whether it
    /// is a duplicate, or `None` if it ends the link.
    const fn classify(&mut self, header: u8, len: u8, mic_ok: bool, address: u32) -> Option<bool> {
        let llid = header & LLID_MASK;
        let maximum = ACL_MAX.saturating_add(if self.encryption.rx_on { MIC_LEN } else { 0 });
        if llid == 0 || usize::from(len) > maximum || (len == 0 && llid != Llid::Continuation.bits()) {
            self.abort = Some(ERROR_INVALID_PARAMETERS);
            return None;
        }
        let duplicate = (header & SN != 0) != self.seq.nesn;
        if duplicate && self.encryption.rx_on {
            self.last_valid = address;
            return Some(true);
        }
        if self.encryption.rx_on && len != 0 && (usize::from(len) <= MIC_LEN || !mic_ok) {
            self.abort = Some(ERROR_MIC_FAILURE);
            return None;
        }
        // Once the central asked to start or pause encryption, it sends no
        // data until encryption runs again (Core, Vol 6, Part B, 5.1.3). Data
        // now could be plain text injected into a link the host trusts as
        // encrypted: end the link before acknowledging it.
        if llid != Llid::Control.bits() && len != 0 && self.encryption.phase != Phase::Idle {
            self.abort = Some(ERROR_MIC_FAILURE);
            return None;
        }
        if self.encryption.rx_on && len != 0 && self.payload_timer.is_some() {
            self.payload_timer = Some((address, false));
        }
        self.last_valid = address;
        self.establishment_deadline = None;
        if duplicate {
            return Some(true);
        }
        // A control PDU waits for processing after the event; data goes to
        // the host at once and needs room there, counted before the event.
        if len != 0 {
            let room = if llid == Llid::Control.bits() { &mut self.room.control } else { &mut self.room.acl };
            if *room == 0 {
                // No room for it: the central sends it again.
                return Some(false);
            }
            *room = room.saturating_sub(1);
        }
        self.seq.nesn = !self.seq.nesn;
        self.seq.received = true;
        Some(false)
    }

    /// Latest time an event that began at `anchor` may still exchange
    /// packets: the next event's receive window opens no earlier than one
    /// interval later, less its widening and setup.
    const fn close_by(&self, anchor: u32) -> u32 {
        anchor
            .wrapping_add(self.interval)
            .wrapping_sub(self.widening(self.interval))
            .wrapping_sub(self.phy.address_offset_us())
            .wrapping_sub(RAMP_UP_US)
            .wrapping_sub(RX_MARGIN_US)
            .wrapping_sub(EVENT_GUARD_US)
    }

    /// Makes the free slot an empty PDU and sends it: the answer to an
    /// acknowledgement when nothing is prepared. Within the interframe
    /// space; the slot is not the one the radio points at. Empty PDUs are
    /// never encrypted, also on an encrypted link.
    const fn commit_empty(&mut self) {
        let next = !self.cur;
        let slot = self.slot_mut(next);
        if let Some(header) = slot.plain.0.first_chunk_mut::<DATA_HEADER_LEN>() {
            *header = [Llid::Continuation.bits(), 0, 0];
        }
        slot.encrypted = false;
        slot.kind = TxKind::Empty;
        slot.source = Source::Empty;
        self.tx_kind = TxKind::Empty;
        self.cur = next;
        self.next_ready = false;
    }

    /// Sends the prepared PDU: takes it off the queue or the host's packet
    /// and uses up its packet counter. Within the interframe space, in a
    /// constant time.
    const fn commit_next(&mut self) {
        let next = !self.cur;
        let slot = self.slot(next);
        let (source, encrypted, kind) = (slot.source, slot.encrypted, slot.kind);
        match source {
            Source::Queue => self.queue.drop_front(),
            Source::Acl { end, last } => {
                if last {
                    self.acl = None;
                } else if let Some(current) = self.acl.as_mut() {
                    current.1 = end;
                } else {
                    // Prepared from the packet, which is still there.
                }
            },
            Source::Empty => {},
        }
        if encrypted {
            self.encryption.tx_counter = self.encryption.tx_counter.saturating_add(1);
        }
        self.tx_kind = kind;
        self.cur = next;
        self.next_ready = false;
    }

    /// Sends `count` `Event::ParamsUpdated` events with `status` and
    /// `params`: the first retained until delivered, any further one if the
    /// host has room.
    fn complete_updates(&mut self, count: u8, status: u8, params: ConnectionParams, shared: &Shared) {
        if count == 0 {
            return;
        }
        self.notify(Event::ParamsUpdated { params, status }, shared);
        // Further events follow the retained ones as the host makes room.
        let (owed, _, _) = self.updates_owed;
        self.updates_owed = (owed.saturating_add(count.saturating_sub(1)), status, params);
        self.flush_notifications(shared);
    }

    /// The slot of the PDU on the air until the central acknowledges it.
    const fn current(&self) -> &TxSlot { self.slot(self.cur) }

    /// The slot of the PDU on the air until the central acknowledges it.
    const fn current_mut(&mut self) -> &mut TxSlot { self.slot_mut(self.cur) }

    /// Current connection parameters in link layer units.
    const fn current_params(&self) -> ConnectionParams {
        ConnectionParams::new(
            self.interval.checked_div(UNIT_1250_US).unwrap_or(0).saturating_cast(),
            self.latency,
            self.timeout.checked_div(UNIT_10MS_US).unwrap_or(0).saturating_cast(),
        )
    }

    /// Decides the answer to a packet within the interframe space. `packet`
    /// is its header, its length and whether its MIC is valid, if its CRC
    /// was; `address` is the time of its access address, and `fits` whether
    /// another exchange fits before the next event. Validates and takes the
    /// packet, takes the acknowledgement of ours, and chooses MD and whether
    /// the event goes on: while either side has more data and it fits. A CRC
    /// error, a control PDU, a packet without room, or a running encryption
    /// or termination procedure closes it. Returns `None` if no answer may
    /// be sent.
    fn decide(
        &mut self,
        packet: Option<(u8, u8, bool)>,
        address: u32,
        fits: bool,
        shared: &Shared,
    ) -> Option<Decision> {
        let mut open =
            fits && self.encryption.phase == Phase::Idle && self.terminate.is_none() && self.terminated.is_none();
        let mut decision = Decision {
            acked:     None,
            central:   None,
            duplicate: false,
            fallback:  false,
            follow:    Follow { md: false, more: false },
            nacked:    false,
        };
        let mut central_more = false;
        if let Some((header, len, mic_ok)) = packet {
            decision.duplicate = self.classify(header, len, mic_ok, address)?;
            let (acked, fallback) = self.ack_fast(header);
            // The central's first packet of the link acknowledges nothing
            // yet.
            decision.nacked = acked.is_none() && self.stats.received != 0;
            decision.acked = acked;
            decision.fallback = fallback;
            decision.central = Some(header);
            central_more = header & MD != 0;
            if self.seq.received {
                // A control PDU can change what the next packets mean: it
                // is handled before the central sends more.
                open &= header & LLID_MASK != Llid::Control.bits();
            } else if !decision.duplicate {
                // No room for it: the central sends it again next event.
                open = false;
            } else {
                // A retransmission acknowledges our packet only.
            }
        } else {
            self.stats.crc_errors = self.stats.crc_errors.wrapping_add(1);
            open = false;
        }
        // Only a prepared PDU goes out in this event, unless the next one
        // is prepared while ours goes out.
        let ours_more = self.next_ready || (chip::PREPARE_IN_EVENT && self.more_waiting(shared));
        decision.follow.md = open && ours_more;
        decision.follow.more = open && (central_more || ours_more);
        Some(decision)
    }

    /// Advances the encryption start procedure with the host's answer.
    #[inline(never)]
    fn drive_encryption(&mut self, shared: &Shared, entropy: &Prefetch) {
        if let Phase::AwaitingEntropy(lookup) = self.encryption.phase {
            let Some(material) = entropy.take() else { return };
            self.finish_encryption_request(lookup, &material);
        }
        let Phase::AwaitingKey(lookup, requested) = self.encryption.phase else { return };
        if !requested {
            if shared.request_ltk(lookup.rand, lookup.ediv) {
                self.encryption.phase = Phase::AwaitingKey(lookup, true);
            }
            return;
        }
        match shared.take_ltk() {
            Some(LtkAnswer::Key(mut ltk)) => {
                let session = crypto::session_key(ltk, self.encryption.skd);
                crypto::wipe(&mut ltk);
                let Some(mut key) = session else {
                    self.abort = Some(ERROR_HARDWARE_FAILURE);
                    return;
                };
                self.encryption.rx_config = crypto::config(key, self.encryption.iv, true);
                self.encryption.tx_config = crypto::config(key, self.encryption.iv, false);
                crypto::wipe(&mut key);
                self.encryption.rx_counter = 0;
                self.encryption.tx_counter = 0;
                crypto::enable();
                self.enqueue(Llid::Control, &[OP_START_ENC_REQ]);
                self.encryption.phase = Phase::Starting;
            },
            Some(LtkAnswer::Missing) if self.encryption.procedure == Procedure::Refresh => {
                // The link stays paused without a key: end it.
                self.abort = Some(ERROR_KEY_MISSING);
            },
            Some(LtkAnswer::Missing) => {
                self.enqueue(Llid::Control, &[OP_REJECT_IND, ERROR_KEY_MISSING]);
                self.encryption.phase = Phase::Idle;
                self.procedure_deadline = None;
                self.encryption_change = Some((ERROR_KEY_MISSING, false));
            },
            None => {},
        }
    }

    /// Services host traffic before the next radio event, a termination the
    /// host asked for first.
    fn drive_host(&mut self, now: u32, shared: &Shared, entropy: &Prefetch) {
        if self.terminate.is_none()
            && let Some(reason) = shared.take_disconnect()
        {
            self.enqueue(Llid::Control, &[OP_TERMINATE_IND, reason]);
            self.terminate = Some((reason, false));
            self.terminate_deadline = Some(now.wrapping_add(self.timeout));
        }
        if self.hold_until.is_some_and(|until| reached(now, until)) {
            self.hold_until = None;
        }
        self.drive_encryption(shared, entropy);
        self.drive_remote_request(now, shared);
        self.drive_length(shared);
        shared.set_rssi(for_phy_mut(&mut self.power, self.tx_phy).average_dbm());
        self.service_queries(now, shared);
        self.start_procedures(now, shared);
    }

    /// Takes a data length the host set for the link, and tells the host of
    /// changed effective lengths (LE Data Length Change).
    fn drive_length(&mut self, shared: &Shared) {
        if let Some(length) = shared.take_data_length() {
            // `start_procedures` tells the central once nothing else runs.
            self.length.local_tx = length;
        }
        let effective = self.length.effective();
        if effective != self.length.reported {
            self.length.reported = effective;
            self.notify(Event::DataLength(effective), shared);
            info!("data length now {} octets out, {} in", effective[0], effective[2]);
        }
    }

    /// Asks the host about a central's connection parameter request and
    /// answers the central as the host decides: with its parameters and the
    /// central's offsets, or with a rejection. A host that does not answer
    /// in [`HOST_REPLY_US`] has the request rejected. Without a host that
    /// decides, the link layer accepts any valid request.
    fn drive_remote_request(&mut self, now: u32, shared: &Shared) {
        if let Some(status) = self.merged_outcome.take() {
            let params = self.current_params();
            self.complete_updates(shared.take_merged_updates(), status, params, shared);
        }
        let Some(request) = self.remote_request else { return };
        if request.asked.is_none() && !shared.host_decides_parameters() {
            // Any parameters the central proposes suit the device.
            self.remote_request = None;
            let mut response: [u8; 24] = [0; 24];
            for (target, source) in response.iter_mut().zip(iter::once(&OP_CONNECTION_PARAM_RSP).chain(&request.params))
            {
                *target = *source;
            }
            self.enqueue(Llid::Control, &response);
            self.remote_update = Some(now.wrapping_add(PROCEDURE_TIMEOUT_US));
            return;
        }
        let Some(deadline) = request.asked else {
            let field = |index: usize| {
                let bytes = request.params.get(index..index.saturating_add(2)).unwrap_or_default();
                bytes.first_chunk::<2>().map_or(0, |&pair| le16(pair))
            };
            let range = ParamRange::new(field(0), field(2), field(4), field(6));
            self.notify(Event::ParamsRequested(range), shared);
            shared.ask_parameters();
            self.remote_request = Some(RemoteRequest { asked: Some(now.wrapping_add(HOST_REPLY_US)), ..request });
            return;
        };
        let reply = match shared.take_parameter_reply() {
            Some(reply) => reply,
            None if reached(now, deadline) => {
                shared.end_parameter_request();
                Err(ERROR_UNACCEPTABLE_PARAMETERS)
            },
            None => return,
        };
        self.remote_request = None;
        match reply {
            Ok(values) => {
                let mut response: [u8; 24] = [0; 24];
                let host = values.iter().flat_map(|&value| le16_bytes(value));
                let offsets = request.params.iter().skip(8).copied();
                for (target, source) in
                    response.iter_mut().zip(iter::once(OP_CONNECTION_PARAM_RSP).chain(host).chain(offsets))
                {
                    *target = source;
                }
                // No preferred periodicity of ours: the central's could exceed
                // the host's interval range, which a central rejects.
                if let Some(periodicity) = response.get_mut(9) {
                    *periodicity = 0;
                }
                self.enqueue(Llid::Control, &response);
                self.remote_update = Some(now.wrapping_add(PROCEDURE_TIMEOUT_US));
            },
            Err(reason) => {
                self.enqueue(Llid::Control, &[OP_REJECT_EXT_IND, OP_CONNECTION_PARAM_REQ, reason]);
                // Commands that were part of an answer the host withdrew.
                self.merged_outcome = Some(reason);
            },
        }
    }

    /// Radio start of event `counter` on the current anchor: the start
    /// [`Self::window`] gives once the counter got there without a packet.
    const fn enable_at(&self, counter: u16) -> u32 {
        let expected =
            self.anchor.wrapping_add(self.interval.wrapping_mul(u32::from(counter.wrapping_sub(self.anchor_counter))));
        expected
            .wrapping_sub(self.widening(expected.wrapping_sub(self.anchor)))
            .wrapping_sub(self.phy.address_offset_us())
            .wrapping_sub(RAMP_UP_US)
            .wrapping_sub(RX_MARGIN_US)
    }

    /// Determines timeouts without allowing received traffic to postpone a
    /// pending local disconnect or the initial connection establishment.
    const fn ended(&self, now: u32) -> Option<Ended> {
        if let Some(reason) = self.abort {
            return Some(Ended::Error(reason));
        }
        if self.procedure_deadline.is_some_and(const |deadline| reached(now, deadline)) {
            return Some(Ended::Error(ERROR_RESPONSE_TIMEOUT));
        }
        if let Some((reason, acknowledged)) = self.terminate
            && (acknowledged || self.terminate_deadline.is_some_and(const |deadline| reached(now, deadline)))
        {
            return Some(Ended::Local(reason));
        }
        if let Some(reason) = self.terminated {
            return Some(Ended::Terminated(reason));
        }
        if self.establishment_deadline.is_some_and(const |deadline| reached(now, deadline)) {
            return Some(Ended::Error(ERROR_FAILED_TO_ESTABLISH));
        }
        if reached(now, self.last_valid.wrapping_add(self.timeout)) {
            return Some(Ended::Lost);
        }
        None
    }

    /// Queues a control PDU.
    const fn enqueue(&mut self, llid: Llid, payload: &[u8]) {
        let mut data: [u8; CONTROL_PAYLOAD_MAX] = [0; CONTROL_PAYLOAD_MAX];
        let len = payload.len().min(CONTROL_PAYLOAD_MAX);
        if let (Some(target), Some(source)) = (data.get_mut(..len), payload.get(..len)) {
            target.copy_from_slice(source);
        }
        if !self.queue.push(Queued { data, len: u8::try_from(len).unwrap_or_default(), llid }) {
            // Losing a control response would strand the peer in a procedure.
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
        }
    }

    /// Runs the connection event: receives the central's packets and
    /// answers each, for as long as either side has more data and another
    /// exchange fits before the next event (Core, Vol 6, Part B, 4.5.6).
    /// Returns the access address time of the first packet, which sets the
    /// anchor even for a packet with a CRC error or a retransmission (Core,
    /// Vol 6, Part B, 4.5.5).
    fn exchange(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &mut Clock<'_>,
        rx: &mut [u8; BUFFER_LEN],
        (enable, deadline): (u32, u32),
        shared: &Shared,
    ) -> Option<u32> {
        // Only LE 2M makes the PHYs differ.
        let asymmetric = chip::PHY_2M && self.phy != self.tx_phy;
        // SAFETY: `rx` is a full packet buffer borrowed for this whole
        // exchange, which disables the radio on every path out.
        let () =
            unsafe { radio.prepare(rx.as_mut_ptr(), if asymmetric { Turnaround::None } else { Turnaround::Transmit }) };
        if !self.arm_decryption(rx) {
            return None;
        }
        let Some(ahead) = clock.receive_ahead(enable) else {
            clock.cancel_start();
            radio.disable();
            crypto::disarm();
            return None;
        };
        // What the setup since TIMER0's restart left of `SETUP_US`.
        self.stats.setup_us_max = self.stats.setup_us_max.max(SETUP_US.saturating_sub(ahead));
        clock.wait_started();
        if !Self::wait_address(radio, clock, deadline) {
            radio.disable();
            crypto::disarm();
            return None;
        }
        self.point_at_current(radio);
        let anchor = clock.address_time();
        let close_by = self.close_by(anchor);
        loop {
            radio.wait_end();
            let fits = !asymmetric && reached(close_by, clock.end_time().wrapping_add(self.exchange_budget_us));
            let Some((more, late)) = self.respond(radio, clock, rx, fits, shared) else {
                radio.disable();
                crypto::disarm();
                return None;
            };
            if asymmetric {
                // The other PHY is set while the radio is disabled, and the
                // answer started from TIMER0 in its place.
                #[cfg(feature = "nrf52832")]
                {
                    radio.wait_disabled();
                    radio.set_phy(self.tx_phy);
                    if !clock.transmit_at(clock.end_time().wrapping_add(self.tx_phy.response_offset_us(self.phy))) {
                        crypto::disarm();
                        self.abort = Some(ERROR_HARDWARE_FAILURE);
                        return None;
                    }
                }
            } else {
                // The switch started the answer; the next turnaround follows
                // its end. On the nRF51 the answer set it already.
                if !TURNAROUND_IN_ANSWER {
                    radio.wait_switched();
                    radio.set_turnaround(if more { Turnaround::Receive } else { Turnaround::None });
                }
                // While ours goes out, the next PDU, into the slot the radio
                // does not send: not after a late answer, which sends it.
                if chip::PREPARE_IN_EVENT && more && !late && !self.next_ready {
                    self.prepare_next(shared);
                }
            }
            radio.wait_end();
            clock.cancel_start();
            if !more {
                break;
            }
            // The switch starts receiving one interframe space after the
            // end; the buffer and the decryption are ready before.
            // SAFETY: as for `prepare` above.
            let () = unsafe { radio.rearm_receive(rx.as_mut_ptr()) };
            if !self.arm_decryption(rx) {
                radio.disable();
                crypto::disarm();
                return Some(anchor);
            }
            radio.wait_switched();
            radio.set_turnaround(Turnaround::Transmit);
            let listen_until = clock
                .end_time()
                .wrapping_add(T_IFS_US)
                .wrapping_add(self.phy.address_offset_us())
                .wrapping_add(RX_TAIL_US);
            if !Self::wait_address(radio, clock, listen_until) {
                radio.disable();
                crypto::disarm();
                return Some(anchor);
            }
            self.point_at_current(radio);
        }
        radio.wait_disabled();
        crypto::disarm();
        Some(anchor)
    }

    /// Air time of a full exchange after the current packet: our answer, and
    /// one more packet each way, at the longest the data lengths allow.
    fn exchange_us(&self) -> u32 {
        // Header, payload, MIC and CRC after the preamble and access
        // address. The S1 byte in RAM is counted as well, which errs on the
        // long side.
        let packet = |phy: Phy, payload: usize, mic: bool| {
            let bytes =
                DATA_HEADER_LEN.saturating_add(payload).saturating_add(if mic { MIC_LEN } else { 0 }).saturating_add(3);
            let octets: u32 = bytes.saturating_cast();
            phy.address_offset_us().saturating_add(octets.saturating_mul(8).checked_div(phy.hci().into()).unwrap_or(0))
        };
        let [_, _, rx_octets, _] = self.length.effective();
        let answer = packet(self.tx_phy, self.tx_payload_max(), self.encryption.tx_on);
        let next = packet(self.phy, usize::from(rx_octets), self.encryption.rx_on);
        answer.saturating_mul(2).saturating_add(next).saturating_add(T_IFS_US.saturating_mul(3))
    }

    /// Updates the encryption phases and the anchor after an exchange whose
    /// access address arrived at `address`.
    const fn exchanged(&mut self, address: u32) {
        if self.encryption.phase == Phase::Starting
            && self.tx_kind == TxKind::Control
            && self.current().plain.0.get(DATA_HEADER_LEN) == Some(&OP_START_ENC_REQ)
        {
            self.encryption.rx_on = true;
            self.encryption.phase = Phase::AwaitingStartResponse;
        }
        // After our encrypted pause response the central answers in
        // plain text.
        if self.encryption.phase == Phase::Pausing
            && self.tx_kind == TxKind::Control
            && self.current().plain.0.get(DATA_HEADER_LEN) == Some(&OP_PAUSE_ENC_RSP)
        {
            self.encryption.rx_on = false;
            self.encryption.phase = Phase::AwaitingPauseResponse;
        }
        if matches!(self.expect, Expect::Anchor) {
            let expected = self.expected_anchor();
            let drift = address.wrapping_sub(expected).cast_signed();
            if drift.unsigned_abs() >= self.drift.0.unsigned_abs() {
                self.drift = (drift, self.widening(expected.wrapping_sub(self.anchor)));
            }
        }
        self.anchor = address;
        self.anchor_counter = self.counter;
        self.expect = Expect::Anchor;
    }

    /// Access address time expected at the current event from the last
    /// anchor.
    const fn expected_anchor(&self) -> u32 {
        let events = u32::from(self.counter.wrapping_sub(self.anchor_counter));
        self.anchor.wrapping_add(self.interval.wrapping_mul(events))
    }

    /// Releases the CCM, overwrites the keys and every packet of the link,
    /// and sets the radio back for advertising once the link ended.
    fn finish(&mut self, radio: &mut Radio<'_>) {
        crypto::disable();
        self.encryption.wipe();
        crypto::wipe(&mut self.rx_plain);
        for held in self.pending.items_mut() {
            crypto::wipe(&mut held.bytes);
        }
        self.pending.clear();
        self.slots.0.wipe();
        self.slots.1.wipe();
        radio.set_s1_included(false);
        radio.set_tx_power(tx_power(DEFAULT_LEVEL));
        radio.set_phy(Phy::M1);
    }

    /// Consumes one complete prefetched block; no hardware RNG work runs here.
    const fn finish_encryption_request(&mut self, lookup: KeyLookup, material: &entropy::Material) {
        let mut response: [u8; 13] = [0; 13];
        if let Some(code) = response.first_mut() {
            *code = OP_ENC_RSP;
        }
        if let Some(own) = response.get_mut(1..) {
            own.copy_from_slice(material.bytes());
        }
        let (own_skd, own_iv) = material.bytes().split_at(8);
        if let Some(target) = self.encryption.skd.get_mut(8..) {
            target.copy_from_slice(own_skd);
        }
        if let Some(target) = self.encryption.iv.get_mut(4..) {
            target.copy_from_slice(own_iv);
        }
        self.enqueue(Llid::Control, &response);
        self.encryption.phase = Phase::AwaitingKey(lookup, false);
    }

    /// First event from `from` up to `last` whose radio start is after
    /// `time`, or `last`. Starts move by at most one interval per event, so
    /// the whole intervals in between are passed at once.
    const fn first_after(&self, from: u16, last: u16, time: u32) -> u16 {
        let span = last.wrapping_sub(from);
        let passed = time.wrapping_sub(self.enable_at(from));
        if !reached(time, self.enable_at(from)) {
            return from;
        }
        let whole = passed.checked_div(self.interval).unwrap_or(0).saturating_cast::<u16>().min(span);
        let mut counter = from.wrapping_add(whole);
        while counter != last && reached(time, self.enable_at(counter)) {
            counter = counter.wrapping_add(1);
        }
        counter
    }

    /// Drains retained notifications before the final disconnection event.
    pub(crate) async fn flush_after_disconnect(&mut self, shared: &Shared) -> bool {
        for slot in &mut self.notifications {
            if let Some(event) = slot.take()
                && matches!(select(shared.push_event(event), shared.reset_requested()).await, Either::Second(()))
            {
                return false;
            }
        }
        while self.updates_owed.0 != 0 {
            let (owed, status, params) = self.updates_owed;
            if matches!(
                select(shared.push_event(Event::ParamsUpdated { params, status }), shared.reset_requested()).await,
                Either::Second(())
            ) {
                return false;
            }
            self.updates_owed.0 = owed.saturating_sub(1);
        }
        true
    }

    /// Flushes retained events in order as host capacity becomes available.
    fn flush_notifications(&mut self, shared: &Shared) {
        while let Some(event) = self.notifications.first().copied().flatten() {
            if !shared.try_push_event(event) {
                return;
            }
            self.notifications.rotate_left(1);
            if let Some(last) = self.notifications.last_mut() {
                *last = None;
            }
        }
        let (owed, status, params) = self.updates_owed;
        for remaining in (0..owed).rev() {
            if !shared.try_push_event(Event::ParamsUpdated { params, status }) {
                break;
            }
            self.updates_owed.0 = remaining;
        }
    }

    /// Answers a control PDU from the central.
    fn handle_control(&mut self, payload: &[u8], encrypted: bool) {
        let Some((&code, params)) = payload.split_first() else { return };
        // While encryption starts or pauses, the central may only take the
        // procedure on or end the link (Core, Vol 6, Part B, 5.1.3). Any
        // other answer would be queued in front of the next step.
        let (allowed, can_answer) = match self.encryption.phase {
            Phase::AwaitingEntropy(_) => (code == OP_TERMINATE_IND, false),
            Phase::Starting | Phase::AwaitingStartResponse => {
                (matches!(code, OP_START_ENC_RSP | OP_TERMINATE_IND), false)
            },
            Phase::Pausing | Phase::AwaitingPauseResponse => {
                (matches!(code, OP_PAUSE_ENC_RSP | OP_TERMINATE_IND), false)
            },
            Phase::Paused => (matches!(code, OP_ENC_REQ | OP_TERMINATE_IND), false),
            Phase::AwaitingKey(..) | Phase::Idle => (true, true),
        };
        if !allowed {
            self.abort = Some(ERROR_PDU_NOT_ALLOWED);
            return;
        }
        if control_len(code).is_some_and(|len| params.len() != len) {
            // A PDU of the wrong length counts as one this side does not
            // know, as in other controllers, unless an answer would get
            // in the way of a running encryption procedure.
            if can_answer {
                self.enqueue(Llid::Control, &[OP_UNKNOWN_RSP, code]);
            } else {
                self.abort = Some(ERROR_INVALID_PARAMETERS);
            }
            return;
        }
        match code {
            OP_CONNECTION_UPDATE_IND | OP_CONNECTION_PARAM_REQ | OP_CONNECTION_PARAM_RSP => {
                self.handle_parameters(code, params);
            },
            OP_CHANNEL_MAP_IND => {
                if let Some([map0, map1, map2, map3, map4, instant0, instant1]) = field::<7>(params, 0) {
                    let map = [map0, map1, map2, map3, map4];
                    let instant = le16([instant0, instant1]);
                    if !valid_channel_map(map) {
                        self.abort = Some(ERROR_INVALID_PARAMETERS);
                    } else if !future_instant(self.counter, instant) {
                        self.abort = Some(ERROR_INSTANT_PASSED);
                    } else if self.channel_update.is_some() || self.param_update.is_some() || self.phy_update.is_some()
                    {
                        self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    } else {
                        self.channel_update = Some((UsedChannels::new(map), instant));
                    }
                }
            },
            OP_TERMINATE_IND => self.terminated = Some(params.first().copied().unwrap_or_default()),
            OP_ENC_REQ | OP_START_ENC_RSP | OP_PAUSE_ENC_REQ | OP_PAUSE_ENC_RSP => {
                self.handle_encryption(code, params, encrypted);
            },
            OP_PHY_REQ | OP_PHY_UPDATE_IND => self.handle_phy(code, params),
            OP_POWER_CONTROL_REQ => self.handle_power(params),
            OP_UNKNOWN_RSP | OP_REJECT_EXT_IND | OP_REJECT_IND => self.handle_rejection(code, params),
            OP_FEATURE_REQ | OP_FEATURE_RSP => self.handle_features(code, params),
            OP_VERSION_IND if self.version.is_none() => {
                let mut response = [OP_VERSION_IND, 0, 0, 0, 0, 0];
                if let Some(target) = response.get_mut(1..) {
                    target.copy_from_slice(&VERSION);
                }
                if !matches!(self.version_request, Request::Requested(_)) {
                    self.enqueue(Llid::Control, &response);
                }
                self.version_request = Request::Done;
                self.version = params.first_chunk::<5>().copied();
            },
            OP_LENGTH_REQ | OP_LENGTH_RSP => {
                self.length.take_peer(params);
                if code == OP_LENGTH_REQ {
                    let response = self.length.pdu(OP_LENGTH_RSP);
                    self.enqueue(Llid::Control, &response);
                } else {
                    self.length.offer_taken();
                    self.length_request = Request::Done;
                }
            },
            OP_PING_REQ => self.enqueue(Llid::Control, &[OP_PING_RSP]),
            OP_PING_RSP => self.ping_request = None,
            OP_VERSION_IND | OP_PHY_RSP | OP_POWER_CONTROL_RSP | OP_POWER_CHANGE_IND => {},
            _ => self.enqueue(Llid::Control, &[OP_UNKNOWN_RSP, code]),
        }
        info!("control {=u8:#04x}", code);
    }

    /// Answers a control PDU of the encryption start and pause procedures.
    fn handle_encryption(&mut self, code: u8, params: &[u8], encrypted: bool) {
        match code {
            OP_ENC_REQ => {
                let refresh = self.encryption.phase == Phase::Paused;
                let fresh = self.encryption.phase == Phase::Idle && !self.encryption.rx_on && !self.encryption.tx_on;
                if !refresh && !fresh {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.encryption.procedure = if refresh { Procedure::Refresh } else { Procedure::First };
                self.procedure_deadline = Some(self.last_valid.wrapping_add(PROCEDURE_TIMEOUT_US));
                self.start_encryption(params);
            },
            OP_START_ENC_RSP => {
                if !encrypted || self.encryption.phase != Phase::AwaitingStartResponse || !self.encryption.rx_on {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.encryption.tx_on = true;
                self.encryption.phase = Phase::Idle;
                self.procedure_deadline = None;
                self.payload_timer = Some((self.last_valid, false));
                self.enqueue(Llid::Control, &[OP_START_ENC_RSP]);
                self.encryption_change = Some((0, true));
                info!("link encrypted");
            },
            OP_PAUSE_ENC_REQ => {
                let on = self.encryption.rx_on && self.encryption.tx_on;
                if !encrypted || !on || self.encryption.phase != Phase::Idle {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                self.procedure_deadline = Some(self.last_valid.wrapping_add(PROCEDURE_TIMEOUT_US));
                self.enqueue(Llid::Control, &[OP_PAUSE_ENC_RSP]);
                self.encryption.phase = Phase::Pausing;
            },
            OP_PAUSE_ENC_RSP => {
                if encrypted || self.encryption.phase != Phase::AwaitingPauseResponse {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                    return;
                }
                // PDUs prepared from now on stay plain. Only an empty PDU can
                // be on the air here, and empty PDUs are never sealed.
                self.encryption.tx_on = false;
                self.encryption.phase = Phase::Paused;
                info!("encryption paused for a key refresh");
            },
            _ => {},
        }
    }

    /// Answers the feature exchange of the central, and takes its answer to
    /// ours. The first byte holds the features both sides use.
    fn handle_features(&mut self, code: u8, params: &[u8]) {
        let Some(&features) = params.first_chunk::<8>() else { return };
        let [central, ..] = features;
        self.central_features = Some(features);
        if code == OP_FEATURE_RSP {
            self.features_request = Request::Done;
            return;
        }
        let mut response = [OP_FEATURE_RSP, 0, 0, 0, 0, 0, 0, 0, 0];
        for (target, source) in response.iter_mut().skip(1).zip(FEATURES) {
            *target = source;
        }
        if let Some(first) = response.get_mut(1) {
            *first &= central;
        }
        self.enqueue(Llid::Control, &response);
    }

    /// Takes connection updates, answers the central's parameter requests
    /// and takes its answer to the host's.
    fn handle_parameters(&mut self, code: u8, params: &[u8]) {
        match code {
            OP_CONNECTION_UPDATE_IND => {
                let Some(mut update) = parse_update(params) else {
                    self.abort = Some(ERROR_INVALID_PARAMETERS);
                    return;
                };
                if !future_instant(self.counter, update.instant) {
                    self.abort = Some(ERROR_INSTANT_PASSED);
                } else if self.param_update.is_some()
                    || self.phy_update.is_some()
                    || self.channel_update.is_some()
                    || self.notifications.iter().flatten().any(Event::is_params_update)
                {
                    self.abort = Some(ERROR_PDU_NOT_ALLOWED);
                } else {
                    // The update answers a request of the host; the host
                    // learns the outcome at the instant.
                    update.requested = self.param_request.take().is_some();
                    self.param_update = Some(update);
                    self.remote_update = None;
                }
            },
            OP_CONNECTION_PARAM_RSP => {
                // Only a peripheral sends this PDU; a central answers our
                // request with UPDATE_IND or REJECT_EXT_IND (Core 5.1.7.2).
                self.abort = Some(ERROR_PDU_NOT_ALLOWED);
            },
            OP_CONNECTION_PARAM_REQ => {
                if !valid_request(params) {
                    self.enqueue(Llid::Control, &[
                        OP_REJECT_EXT_IND,
                        OP_CONNECTION_PARAM_REQ,
                        ERROR_INVALID_PARAMETERS,
                    ]);
                } else if self.param_update.is_some()
                    || self.phy_update.is_some()
                    || self.channel_update.is_some()
                    || self.notifications.iter().flatten().any(Event::is_params_update)
                {
                    self.enqueue(Llid::Control, &[
                        OP_REJECT_EXT_IND,
                        OP_CONNECTION_PARAM_REQ,
                        ERROR_DIFFERENT_TRANSACTION,
                    ]);
                } else if let Some(&request) = params.first_chunk::<23>() {
                    // Answered before the next event, by the host if it
                    // decides on such requests.
                    self.remote_request = Some(RemoteRequest { asked: None, params: request });
                } else {
                    // Too short: `valid_request` let it through.
                }
            },
            _ => {},
        }
    }

    /// Answers the PDUs of the PHY update procedure.
    fn handle_phy(&mut self, code: u8, params: &[u8]) {
        if code == OP_PHY_REQ {
            if !chip::PHY_2M {
                // With LE 1M alone the PHY update procedure is not
                // supported (Core, Vol 6, Part B, 5.1.10): the central
                // learns it as for any unknown PDU.
                self.enqueue(Llid::Control, &[OP_UNKNOWN_RSP, OP_PHY_REQ]);
                return;
            }
            if field::<2>(params, 0).is_none_or(|[tx, rx]| tx.trailing_zeros() >= 2 || rx.trailing_zeros() >= 2) {
                self.enqueue(Llid::Control, &[OP_REJECT_EXT_IND, OP_PHY_REQ, ERROR_UNSUPPORTED_VALUE]);
                return;
            }
            // The central's procedure takes the place of ours.
            self.phy_request = Request::Requested(self.last_valid.wrapping_add(PROCEDURE_TIMEOUT_US));
            let [tx, rx] = self.preferred_phys;
            self.enqueue(Llid::Control, &[OP_PHY_RSP, tx, rx]);
            return;
        }
        let Some([to_peripheral, to_central, instant0, instant1]) = field::<4>(params, 0) else { return };
        self.phy_request = Request::Done;
        if to_peripheral == 0 && to_central == 0 {
            if self.host_phy.is_some() {
                self.phy_status = Some(STATUS_SUCCESS);
            }
            return;
        }
        let keep = self.phy.hci();
        let receive = Phy::from_bits(if to_peripheral == 0 { keep } else { to_peripheral });
        let send = Phy::from_bits(if to_central == 0 { self.tx_phy.hci() } else { to_central });
        // Each direction keeps its own PHY. Asymmetric exchanges disable
        // the RX-to-TX shortcut and use a compensated TIMER/PPI start.
        let (Some(phy), Some(other)) = (receive, send) else {
            self.abort = Some(ERROR_UNSUPPORTED_VALUE);
            return;
        };
        let instant = le16([instant0, instant1]);
        if !future_instant(self.counter, instant) {
            self.abort = Some(ERROR_INSTANT_PASSED);
        } else if self.phy_update.is_some()
            || self.param_update.is_some()
            || self.channel_update.is_some()
            || self.notifications.iter().flatten().any(Event::is_phy_update)
        {
            self.abort = Some(ERROR_PDU_NOT_ALLOWED);
        } else if phy != self.phy || other != self.tx_phy {
            self.next_tx_phy = other;
            self.phy_update = Some((phy, instant));
        } else if self.host_phy.is_some() {
            self.phy_status = Some(STATUS_SUCCESS);
        } else {
            // The PHY stays: nothing changes at the instant, and the host,
            // which did not ask, learns nothing (Core, Vol 4, Part E,
            // 7.7.65.12).
        }
    }

    /// Answers the central's request to change the own transmit power by a
    /// delta, with the power now used and how far the central could lower
    /// its own. An unknown acceptable reduction is reported as 0xFF.
    fn handle_power(&mut self, params: &[u8]) {
        let Some([phy, delta, central_power]) = field::<3>(params, 0) else { return };
        let error = if Phy::from_bits(phy).is_none() {
            Some(ERROR_UNSUPPORTED_VALUE)
        } else if central_power == 126 {
            Some(ERROR_INVALID_PARAMETERS)
        } else {
            None
        };
        if let Some(reason) = error {
            self.enqueue(Llid::Control, &[OP_REJECT_EXT_IND, OP_POWER_CONTROL_REQ, reason]);
            return;
        }
        let Some(request_phy) = Phy::from_bits(phy) else { return };
        let before = tx_power(for_phy_mut(&mut self.power, request_phy).level());
        let requested = if delta == 0x7F {
            i32::from(i8::MAX)
        } else {
            i32::from(before).saturating_add(i32::from(delta.cast_signed()))
        };
        // Round upward to the lowest available power at least as high as
        // requested.
        let requested_level =
            LEVELS_DBM.iter().copied().find(|&level| i32::from(level) >= requested).unwrap_or(MAX_POWER_DBM);
        for_phy_mut(&mut self.power, request_phy).move_to(i32::from(requested_level));
        self.power_reporting |= phy;
        let level = for_phy_mut(&mut self.power, request_phy).level();
        let now = tx_power(level);
        let change = i8::try_from(i32::from(now).saturating_sub(i32::from(before))).unwrap_or_default();
        let reduction = UNKNOWN_REDUCTION;
        self.enqueue(Llid::Control, &[
            OP_POWER_CONTROL_RSP,
            limit_flags(level),
            change.cast_unsigned(),
            now.cast_unsigned(),
            reduction,
        ]);
        *for_phy_mut(&mut self.announced_power, request_phy) = level;
    }

    /// Takes the central's refusal of a procedure of ours: an unknown
    /// response or a rejection naming the procedure, or a plain rejection,
    /// which can only answer a connection parameter request.
    const fn handle_rejection(&mut self, code: u8, params: &[u8]) {
        let (opcode, error) = match (code, params) {
            (OP_UNKNOWN_RSP, &[opcode]) => (opcode, ERROR_UNSUPPORTED_FEATURE),
            (OP_REJECT_EXT_IND, &[opcode, error]) => (opcode, error),
            (OP_REJECT_IND, &[error]) => (OP_CONNECTION_PARAM_REQ, error),
            _ => return,
        };
        match opcode {
            OP_PHY_REQ => {
                self.phy_request = Request::Done;
                if self.host_phy.is_some() {
                    self.phy_status = Some(error);
                }
            },
            OP_PERIPHERAL_FEATURE_REQ => {
                self.features_request = Request::Done;
                if self.host_queries & 1 != 0 {
                    self.feature_error = Some(error);
                }
            },
            OP_PING_REQ => self.ping_request = None,
            OP_LENGTH_REQ => {
                self.length_request = Request::Done;
                self.length.unsupported = true;
                self.length.offered_tx = None;
            },
            OP_CONNECTION_PARAM_REQ if self.param_request.is_some() => {
                self.param_request = None;
                self.param_status = Some(error);
            },
            // The central ended its own request after our response, naming
            // the response as the specification says, or its request.
            OP_CONNECTION_PARAM_REQ | OP_CONNECTION_PARAM_RSP => {
                if self.remote_update.is_some() {
                    self.merged_outcome = Some(error);
                }
                self.remote_update = None;
            },
            _ => {},
        }
    }

    /// Holds the peripheral latency off until [`LATENCY_HOLD_US`] or
    /// [`LATENCY_HOLD_EVENTS`] intervals after `time`, whichever is later,
    /// unless it is held longer already.
    const fn hold_latency_from(&mut self, time: u32) {
        let span = LATENCY_HOLD_US.max(self.interval.saturating_mul(LATENCY_HOLD_EVENTS));
        let until = time.wrapping_add(span);
        if self.hold_until.is_none_or(const |current| reached(until, current)) {
            self.hold_until = Some(until);
        }
    }

    /// Event to listen at after skipping from the current one: as many as
    /// the latency leaves.
    const fn listen_counter(&self) -> u16 { self.counter.wrapping_add(self.latency.saturating_sub(self.skipped)) }

    /// Ends listening at an event that [`Self::listening`] began, with the
    /// time of the last valid packet it returned. If no packet with a valid
    /// CRC came from the central in the event, the next event is listened at
    /// too, and every one after it until a packet comes, so that a lost
    /// anchor is found again one interval later rather than after the whole
    /// peripheral latency, which a short supervision timeout could not wait
    /// for. Zephyr's peripheral does the same: it breaks the latency while
    /// its supervision timer runs. The latency resumes after the first event
    /// that hears the central.
    const fn listened(&mut self, heard_before: u32) {
        if self.last_valid == heard_before {
            self.skipped = self.latency;
        }
    }

    /// Begins listening at the current event: counts it as listened at for
    /// the peripheral latency. Returns the time of the last valid packet,
    /// which [`Self::listened`] takes after the event.
    const fn listening(&mut self) -> u32 {
        self.skipped = 0;
        self.last_valid
    }

    /// Logs what the event's trace holds: the control PDUs this side sent
    /// and the central acknowledged, and in the first events of the link
    /// the headers of the first exchange.
    fn log_trace(&mut self) {
        let trace = mem::take(&mut self.trace);
        for &(sent, opcode) in trace.controls.iter().take(usize::from(trace.count)) {
            if sent {
                info!("sent control {=u8:#04x} at event {}", opcode, self.counter);
            } else {
                info!("control {=u8:#04x} acked at event {}", opcode, self.counter);
            }
        }
        if let Some((central, ours, late)) = trace.first {
            info!("event {}: central header {=u8:#04x}, ours {=u8:#04x}, late {}", self.counter, central, ours, late);
        }
    }

    /// Whether more of ours waits than the prepared PDU: a control PDU, the
    /// host's packet or more of it, or a packet the host queued.
    fn more_waiting(&self, shared: &Shared) -> bool {
        !self.queue.is_empty() || self.acl.is_some() || shared.has_acl_out()
    }

    /// Starts a connection from a request whose packet ended at `end`.
    #[inline]
    #[must_use = "the connection does nothing until run"]
    pub fn new(request: &ConnectInd, end: u32) -> Self {
        let interval = u32::from(request.interval).saturating_mul(UNIT_1250_US);
        let start =
            end.wrapping_add(UNIT_1250_US).wrapping_add(u32::from(request.win_offset).saturating_mul(UNIT_1250_US));
        // The fields with a scalar starting value take it from the struct.
        // The aggregates are built here: a default field value is a
        // constant, which the compiler copies from flash or clears with a
        // call instead of storing it in place, about 0.3 KB more flash in a
        // firmware for the same values.
        Self {
            acl: None,
            length: DataLength::new(LENGTH_DEFAULT),
            notifications: [None; 3],
            anchor: end,
            announced_power: [DEFAULT_LEVEL; 2],
            central_features: None,
            channel_update: None,
            drift: NO_DRIFT,
            hopping: if request.csa2 { Hopping::csa2(request.access_address) } else { Hopping::new(request.hop) },
            encryption: Encryption {
                iv:         [0; 8],
                phase:      Phase::Idle,
                procedure:  Procedure::First,
                rx_config:  [0; CONFIG_LEN],
                rx_counter: 0,
                rx_on:      false,
                scratch:    [0; SCRATCH_LEN],
                skd:        [0; 16],
                tx_config:  [0; CONFIG_LEN],
                tx_counter: 0,
                tx_on:      false,
            },
            encryption_change: None,
            establishment_deadline: Some(start.wrapping_add(interval.saturating_mul(6))),
            expect: Expect::Window { start, size: u32::from(request.win_size).saturating_mul(UNIT_1250_US) },
            interval,
            last_valid: end,
            latency: request.latency,
            map: UsedChannels::new(request.channel_map),
            param_update: None,
            payload_timer: None,
            phy_update: None,
            power: [PowerControl::new(); 2],
            report_at: end.wrapping_add(REPORT_INTERVAL_US),
            reported: (Stats::default(), 0),
            queue: Ring::new(Queued { data: [0; CONTROL_PAYLOAD_MAX], len: 0, llid: Llid::Continuation }),
            pending: Ring::new(Pending { bytes: [0; DATA_HEADER_LEN + CONTROL_PAYLOAD_MAX], encrypted: false }),
            room: Room { acl: 0, control: 0 },
            peaks: Peaks::default(),
            trace: Trace::default(),
            slots: (TxSlot::empty(), TxSlot::empty()),
            remote_request: None,
            updates_owed: (
                0,
                STATUS_SUCCESS,
                ConnectionParams::new(request.interval, request.latency, request.timeout),
            ),
            rx_plain: [0; BUFFER_LEN],
            sca_ppm: request.sca_ppm.saturating_add(chip::sleep_clock_ppm()),
            stats: Stats::default(),
            terminate: None,
            timeout: u32::from(request.timeout).saturating_mul(UNIT_10MS_US),
            version: None,
            hold_until: Some(end.wrapping_add(LATENCY_HOLD_START_US)),
            host_phy: None,
            preferred_phys: [PREFERRED_PHYS; 2],
            seq: Sequence { .. },
            ..
        }
    }

    /// Earliest time at which the loop top acts without a packet or a host
    /// wakeup: supervision, procedure and reply deadlines, and the ping
    /// point and expiry of the authenticated payload timeout.
    fn next_deadline(&self, now: u32, shared: &Shared) -> u32 {
        let requests = [self.features_request, self.phy_request, self.length_request, self.version_request]
            .into_iter()
            .filter_map(|request| if let Request::Requested(deadline) = request { Some(deadline) } else { None });
        let payload = self.payload_timer.into_iter().flat_map(|(last, pinged)| {
            let timeout = shared.payload_timeout();
            let ping = (!pinged).then(|| last.wrapping_add(timeout.saturating_sub(timeout.wrapping_shr(2))));
            ping.into_iter().chain(iter::once(last.wrapping_add(timeout)))
        });
        [
            Some(self.last_valid.wrapping_add(self.timeout)),
            self.procedure_deadline,
            self.terminate_deadline,
            self.establishment_deadline,
            self.param_request,
            self.ping_request,
            self.remote_update,
            self.remote_request.and_then(|request| request.asked),
        ]
        .into_iter()
        .flatten()
        .chain(requests)
        .chain(payload)
        // A deadline already passed sorts first: the batch then ends at once.
        .min_by_key(|deadline| deadline.wrapping_sub(now).cast_signed())
        .unwrap_or_else(|| now.wrapping_add(self.timeout))
    }

    /// Counts a missed event and moves an expected transmit window to the
    /// next event.
    fn note_miss(&mut self, channel: u8, window: (u32, u32)) {
        self.stats.missed = self.stats.missed.wrapping_add(1);
        // Tells timing from the radio: how long since the last packet, how
        // long the radio listened, and whether a transmit window after a
        // parameter update was expected.
        info!(
            "missed event {}: channel {}, {} events and {} us after the last packet, listened {} us, window {}, 2M {}",
            self.counter,
            channel,
            self.counter.wrapping_sub(self.anchor_counter),
            window.1.wrapping_sub(self.anchor),
            window.1.wrapping_sub(window.0),
            !matches!(self.expect, Expect::Anchor),
            self.phy == Phy::M2
        );
        if let Expect::Window { start, size } = self.expect {
            self.expect = Expect::Window { start: start.wrapping_add(self.interval), size };
        }
    }

    /// Retains a host notification without blocking radio progress.
    pub(crate) fn notify(&mut self, event: Event, shared: &Shared) {
        if self.notifications.iter().all(Option::is_none) && shared.try_push_event(event) {
            return;
        }
        if let Some(slot) = self.notifications.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(event);
        } else {
            self.abort = Some(ERROR_HARDWARE_FAILURE);
        }
    }

    /// Points the radio at the PDU on the air, right after the access
    /// address of a received packet, when the reception latched its own
    /// buffer already: the pointer then applies to the answer. An answer
    /// decided too late sends it again rather than the received packet.
    fn point_at_current(&mut self, radio: &mut Radio<'_>) {
        let buffer = self.current_mut().on_air().0.as_mut_ptr();
        // SAFETY: the slots belong to this connection, and the exchange
        // disables the radio before it returns.
        let () = unsafe { radio.set_buffer(buffer) };
        radio.clear_ready();
    }

    /// Prepares the coming event again once TIMER0 restarted for it, at the
    /// time `now` reads, for a radio start at `start`, if the host passed
    /// something while the crystal started, or `refused`: a wake of the sleep
    /// [`Self::prepare_after_wake`] refused, which took the host's signal. The
    /// sleep listens for the host only until the crystal starts, or until
    /// [`SETUP_US`] before the start where TIMER0 kept running, so the data
    /// would otherwise wait for the next event. Only while
    /// [`PREPARE_LATE_US`] remain, and only where the chip does it
    /// ([`chip::PREPARE_AFTER_RESTART`]); elsewhere it does nothing, and the
    /// host's signal stays for the next sleep. Returns whether it prepared
    /// again.
    fn prepare_after_restart(&mut self, refused: bool, now: impl FnOnce() -> u32, start: u32, shared: &Shared) -> bool {
        chip::PREPARE_AFTER_RESTART
            && (shared.take_wakeup() || refused)
            && self.prepare_within(now(), PREPARE_LATE_US, start, shared)
    }

    /// Prepares the coming event again after the host woke the sleep before
    /// it, at `now`, for a radio start at `start`: the host's data queued
    /// during the sleep, unless a PDU is prepared already, and the room its
    /// reading made. Only as long as this ends before the radio's setup;
    /// otherwise the data waits for the next event. Returns whether it
    /// prepared again.
    fn prepare_after_wake(&mut self, now: u32, start: u32, shared: &Shared) -> bool {
        self.prepare_within(now, SETUP_US.saturating_add(PREPARE_AGAIN_US), start, shared)
    }

    /// Prepares the coming event outside the interframe space, so that the
    /// answer within it only decides: the next PDU, timed, the air time of
    /// another exchange, and the room for the central's packets.
    fn prepare_event(&mut self, clock: &Clock<'_>, shared: &Shared) {
        let started = clock.now();
        self.prepare_next(shared);
        if clock.is_running() {
            let took = clock.now().wrapping_sub(started);
            self.peaks.prepare = self.peaks.prepare.max(took);
            self.stats.prepare_us_max = self.stats.prepare_us_max.max(took);
        }
        self.prepare_room(shared);
    }

    /// Prepares the next PDU in the free slot, between events, or on the
    /// nRF52832 also while our answer goes out: the first control PDU,
    /// otherwise the next fragment of the host's data, which waits while
    /// encryption starts or pauses, otherwise an empty PDU. It copies the
    /// payload and, on an encrypted link, seals it with the next packet
    /// counter, but takes nothing off yet: running it again before the next
    /// event prepares the same PDU, or what came first meanwhile, with the
    /// same counter, as a PDU only uses up its counter once it is sent.
    fn prepare_next(&mut self, shared: &Shared) {
        let idle = self.encryption.phase == Phase::Idle;
        if self.acl.is_none() && self.queue.is_empty() && idle {
            self.acl = shared.next_acl_out().map(|packet| (packet, 0));
        }
        let limit = self.tx_payload_max();
        let free = !self.cur;
        let slot = if free { &mut self.slots.1 } else { &mut self.slots.0 };
        let payload = slot.plain.0.get_mut(DATA_HEADER_LEN..).unwrap_or_default();
        let (kind, llid, len, source) = if let Some(control) = self.queue.front() {
            let size = usize::from(control.len);
            if let (Some(target), Some(data)) = (payload.get_mut(..size), control.data.get(..size)) {
                target.copy_from_slice(data);
            }
            let kind =
                if control.data.first() == Some(&OP_TERMINATE_IND) { TxKind::Terminate } else { TxKind::Control };
            (kind, control.llid, control.len, Source::Queue)
        } else if let Some(current) = self.acl.as_ref().filter(|_| idle) {
            let packet = &current.0;
            let start = usize::from(current.1);
            let size = usize::from(packet.len).saturating_sub(start).min(limit);
            let end = start.saturating_add(size);
            if let (Some(target), Some(data)) = (payload.get_mut(..size), packet.data.get(start..end)) {
                target.copy_from_slice(data);
            }
            let llid = if start == 0 { packet.llid } else { Llid::Continuation };
            let last = end >= usize::from(packet.len);
            let source = Source::Acl { end: u8::try_from(end).unwrap_or(u8::MAX), last };
            (if last { TxKind::Acl } else { TxKind::AclPart }, llid, u8::try_from(size).unwrap_or(u8::MAX), source)
        } else {
            (TxKind::Empty, Llid::Continuation, 0, Source::Empty)
        };
        if let Some(header) = slot.plain.0.first_chunk_mut::<DATA_HEADER_LEN>() {
            // The S1 byte stays zero: on the nRF51 its bits are sent as the
            // top bits of the length.
            *header = [llid.bits(), len, 0];
        }
        slot.kind = kind;
        slot.source = source;
        slot.encrypted = self.encryption.tx_on && len != 0;
        self.next_ready = kind != TxKind::Empty;
        if !slot.encrypted {
            return;
        }
        if !crypto::set_counter(&mut self.encryption.tx_config, self.encryption.tx_counter) {
            self.abort = Some(ERROR_MIC_FAILURE);
            self.next_ready = false;
            return;
        }
        let pointers = (slot.plain.0.as_ptr(), slot.sealed.0.as_mut_ptr());
        // SAFETY: the configuration, scratch and both buffers belong to this
        // connection, the CCM is done with them when `seal` returns, and no
        // decryption is armed: between events, or while our answer goes out
        // after the received packet was decrypted.
        let sealed =
            unsafe { crypto::seal(&self.encryption.tx_config, pointers, &mut self.encryption.scratch, self.tx_phy) };
        if !sealed {
            self.abort = Some(ERROR_HARDWARE_FAILURE);
            self.next_ready = false;
        }
    }

    /// The air time of another exchange at the current lengths, and the room
    /// for the central's packets in the coming event.
    fn prepare_room(&mut self, shared: &Shared) {
        self.exchange_budget_us = self.exchange_us();
        let free = RX_SLOTS.saturating_sub(self.pending.len());
        // Data waits while the host has not got the link's start, so it
        // never learns of data before the link.
        let acl = if self.notifications.iter().flatten().any(Event::is_connected) { 0 } else { shared.acl_room() };
        self.room = Room { acl: acl.saturating_cast(), control: free.saturating_cast() };
    }

    /// Prepares the coming event again at `now` for a radio start at
    /// `start`, if more than `needed` microseconds remain until it: the
    /// host's data, unless a PDU is prepared already, and the room the host's
    /// reading made. Returns whether it prepared again.
    fn prepare_within(&mut self, now: u32, needed: u32, start: u32, shared: &Shared) -> bool {
        if reached(now.wrapping_add(needed), start) {
            return false;
        }
        if !self.next_ready {
            self.prepare_next(shared);
        }
        self.prepare_room(shared);
        true
    }

    /// Handles the control PDUs received in the event, in order, and reports
    /// acknowledged ACL data.
    #[inline(never)]
    fn process(&mut self, rx: &[u8; BUFFER_LEN], encrypted: bool, shared: &Shared) {
        self.flush_notifications(shared);
        if self.seq.received {
            self.stash(rx, encrypted, shared);
        }
        while let Some(held) = self.pending.front_mut() {
            let mut packet = *held;
            crypto::wipe(&mut held.bytes);
            self.pending.drop_front();
            let [header, length, ..] = packet.bytes;
            let len = usize::from(length);
            match packet.bytes.get(DATA_HEADER_LEN..DATA_HEADER_LEN.saturating_add(len)) {
                Some(payload) if header & LLID_MASK == Llid::Control.bits() => {
                    self.handle_control(payload, packet.encrypted);
                },
                Some(_) | None => {},
            }
            crypto::wipe(&mut packet.bytes);
        }
        if let Some((status, enabled)) = self.encryption_change {
            let refresh = self.encryption.procedure == Procedure::Refresh;
            let event = Event::Encryption { on: enabled, refresh, status };
            if shared.try_push_event(event) {
                self.encryption_change = None;
                self.encryption.procedure = Procedure::First;
            }
        }
        self.report_parameters(shared);
        if self.completed != 0 {
            shared.acknowledged(mem::take(&mut self.completed));
        }
        self.log_trace();
    }

    /// Tells the host when the radio starts for the event the link layer is
    /// to listen at, at `start` on its clock, and by when data has to be
    /// queued to go out then ([`crate::link::Link::next_connection_event`]).
    /// Only the host's time and a few words are taken here; the host
    /// converts them when it asks.
    #[cfg(feature = "event-timing")]
    fn publish_event(&self, clock: &Clock<'_>, start: u32, shared: &Shared) {
        let ahead = start.wrapping_sub(clock.now());
        shared.set_next_event(embassy_time::Instant::now(), ahead, queue_lead(clock.lead()), self.interval);
    }

    /// Logs the counters since the last call.
    fn report(&mut self, (late, lead): (u32, u32)) {
        let (last, last_late) = self.reported;
        info!(
            "10 s: {} events, {} skipped, {} missed, {} crc errors, {} packets, {} late crystal (lead {} us), {} dBm, drift {} of +-{} us",
            self.stats.events.wrapping_sub(last.events),
            self.stats.skipped.wrapping_sub(last.skipped),
            self.stats.missed.wrapping_sub(last.missed),
            self.stats.crc_errors.wrapping_sub(last.crc_errors),
            self.stats.received.wrapping_sub(last.received),
            late.wrapping_sub(last_late),
            lead,
            tx_power(for_phy_mut(&mut self.power, self.tx_phy).level()),
            self.drift.0,
            self.drift.1
        );
        info!(
            "10 s: {} retx ({} with ack), {} acked ({} data), {} late ({} on ack), answer max {} us (ack {} us), {} fallback, prepare max {} us",
            self.stats.retx.wrapping_sub(last.retx),
            self.stats.retx_with_ack.wrapping_sub(last.retx_with_ack),
            self.stats.acked.wrapping_sub(last.acked),
            self.stats.acked_data.wrapping_sub(last.acked_data),
            self.stats
                .late_ack
                .wrapping_add(self.stats.late_noack)
                .wrapping_sub(last.late_ack.wrapping_add(last.late_noack)),
            self.stats.late_ack.wrapping_sub(last.late_ack),
            self.peaks.answer,
            self.peaks.answer_ack,
            self.stats.fallback.wrapping_sub(last.fallback),
            self.peaks.prepare
        );
        self.peaks = Peaks::default();
        self.drift = NO_DRIFT;
        self.reported = (self.stats, late);
        self.report_at = self.report_at.wrapping_add(REPORT_INTERVAL_US);
    }

    /// Reports a connection parameter request of the host that ended without
    /// an update.
    fn report_parameters(&mut self, shared: &Shared) {
        if let Some(status) = self.param_status
            && shared.try_push_event(Event::ParamsUpdated { params: self.current_params(), status })
        {
            self.param_status = None;
            shared.finish_param_request();
        }
    }

    /// Answers the packet that just ended, within the interframe space. A
    /// packet with a CRC error is answered too, with the unacknowledged PDU
    /// again (Core, Vol 6, Part B, 4.5.6). Returns `None` if no answer may
    /// be sent, and otherwise whether the event goes on after the answer
    /// (see [`Self::decide`]) and whether the answer came too late.
    ///
    /// The radio latches the packet pointer when the answer starts, about
    /// 140 us after the END on the nRF51, and sends whatever it points at.
    /// Since the access address it points at the PDU on the air
    /// ([`Self::point_at_current`]), so the answer only decides, switches
    /// to the prepared slot and patches the header flags, in a few hundred
    /// cycles, before anything else: an answer that comes too late resends
    /// our previous PDU with its previous flags, a retransmission the
    /// central recovers from, and never echoes the received packet. Within
    /// the interframe space nothing writes to the buffer the radio points
    /// at but that header byte, nothing copies, seals or searches a queue,
    /// and nothing asks the host; the received packet is stashed, and the
    /// signal strength and the counters are taken, once the answer is in
    /// place. A function of its own, outside the event loop's future, so
    /// its cycles can be counted on the firmware's ELF.
    #[inline(never)]
    fn respond(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &Clock<'_>,
        rx: &[u8; BUFFER_LEN],
        fits: bool,
        shared: &Shared,
    ) -> Option<(bool, bool)> {
        // The decryption of the packet started at its access address; the
        // CCM must not start again at ours.
        crypto::disarm();
        let packet = if radio.crc_ok() {
            let header = rx.first().copied().unwrap_or_default();
            let len = rx.get(1).copied().unwrap_or_default();
            let mic_ok = if self.encryption.rx_on && len != 0 {
                let Some(valid) = crypto::wait_decrypted() else {
                    self.abort = Some(ERROR_HARDWARE_FAILURE);
                    return None;
                };
                valid
            } else {
                true
            };
            Some((header, len, mic_ok))
        } else {
            // Its length may be corrupt: the decryption is not waited for.
            if self.encryption.rx_on {
                crypto::stop();
            }
            None
        };
        let decision = self.decide(packet, clock.address_time(), fits, shared)?;
        #[cfg(feature = "ifs-delay-test")]
        if decision.acked.is_some() && self.counter.trailing_zeros() >= 4 {
            clock.wait_until(clock.end_time().wrapping_add(IFS_DELAY_TEST_US));
        }
        let buffer = self.answer_buffer(decision.follow.md);
        // SAFETY: the slots belong to this connection, and the exchange
        // disables the radio before it returns.
        let () = unsafe { radio.set_buffer(buffer) };
        if TURNAROUND_IN_ANSWER {
            // Before our answer ends, also a late one: the radio's own
            // turnaround follows that END (see `switch_tifs`).
            radio.wait_switched();
            radio.set_turnaround(if decision.follow.more { Turnaround::Receive } else { Turnaround::None });
        }
        let late = radio.tx_started();
        let answer_us = clock.now().wrapping_sub(clock.end_time());
        self.after_answer(decision, rx, (radio.rssi(), late, answer_us), shared);
        Some((decision.follow.more, late))
    }

    /// Runs connection events until the connection ends, exchanging data and
    /// events with the host through `shared`.
    #[inline]
    pub async fn run(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &mut Clock<'_>,
        rx: &mut [u8; BUFFER_LEN],
        shared: &Shared,
    ) -> (Ended, Stats) {
        let entropy = Prefetch::new();
        match select(self.run_events(radio, clock, rx, shared, &entropy), entropy.run()).await {
            Either::First(result) => result,
            Either::Second(never) => never,
        }
    }

    /// Schedules radio events independently of entropy collection progress.
    async fn run_events(
        &mut self,
        radio: &mut Radio<'_>,
        clock: &mut Clock<'_>,
        rx: &mut [u8; BUFFER_LEN],
        shared: &Shared,
        entropy: &Prefetch,
    ) -> (Ended, Stats) {
        radio.set_s1_included(true);
        self.start_slots(shared);
        let ended = loop {
            if shared.take_reset() {
                break Ended::Reset;
            }
            self.flush_notifications(shared);
            health::checkpoint(10);
            // Flash runs between two events, with the radio parked.
            if maintenance::pending() {
                maintenance::service(clock, radio).await;
                health::checkpoint(10);
            }
            if let Some(ended) = self.ended(clock.now()) {
                break ended;
            }
            self.drive_host(clock.now(), shared, entropy);
            if let Some(reason) = self.abort {
                break Ended::Error(reason);
            }
            self.apply_instants(shared);
            let channel = self.hopping.channel(&self.map, self.counter);
            let window = self.window();
            // An anchor that passed during a flash pause is skipped, as with
            // latency; a transmit window is searched in the miss path below.
            if matches!(self.expect, Expect::Anchor) && reached(clock.now(), window.0) {
                self.stats.skipped = self.stats.skipped.wrapping_add(1);
                self.counter = self.counter.wrapping_add(1);
                continue;
            }
            shared.reset_wakeup();
            if self.skips(clock.now(), shared) {
                // One sleep for the whole run of skipped events, ending where
                // the event-by-event loop would last have woken: at the start
                // of the last skipped event, or of the first one at or after
                // a deadline the loop top acts on.
                let listen = self.listen_counter();
                let last = listen.wrapping_sub(1);
                let deadline = self.next_deadline(clock.now(), shared);
                let stop = self.first_after(self.counter, last, deadline.wrapping_sub(1));
                let until = self.enable_at(stop);
                #[cfg(feature = "event-timing")]
                self.publish_event(clock, self.enable_at(listen), shared);
                let woken = select(shared.wakeup(), maintenance::requested());
                let timed_out = clock.idle_until(until, woken).await;
                health::checkpoint(10);
                // The RTC1 alarm may end the sleep up to a tick before `until`
                // on this clock.
                let now = clock.now();
                let time = if timed_out && !reached(now, until) { until } else { now };
                // Events whose radio start passed during the sleep are skipped.
                let next = self.first_after(self.counter, listen, time);
                if next != self.counter {
                    self.skip_to(next, shared);
                    if !timed_out {
                        // As before: the host's data goes out at the next
                        // event.
                        self.skipped = self.latency;
                    }
                    continue;
                }
                // Woken before the current event: listen at it, as before.
                self.skipped = self.latency;
            }
            self.prepare_event(clock, shared);
            if let Some(reason) = self.abort {
                break Ended::Error(reason);
            }
            #[cfg(feature = "event-timing")]
            self.publish_event(clock, window.0, shared);
            // The host runs while the link layer sleeps: what it queues then
            // wakes the sleep and is prepared again, so that it goes out at
            // this event rather than the next.
            // A wake too close to the event for that is remembered, as it
            // took the host's signal.
            let mut refused = false;
            while !clock.sleep_until(window.0, shared.wakeup()).await {
                refused |= !self.prepare_after_wake(clock.now(), window.0, shared);
            }
            // The sleep listens for the host only until the crystal starts;
            // what the host queued since, or in a wake refused above, is
            // prepared once TIMER0 runs, where the chip has the time.
            self.prepare_after_restart(refused, || clock.now(), window.0, shared);
            if let Some(reason) = self.abort {
                break Ended::Error(reason);
            }
            if !clock.ensure_crystal().await && reached(clock.now(), window.0) {
                self.stats.skipped = self.stats.skipped.wrapping_add(1);
                self.counter = self.counter.wrapping_add(1);
                continue;
            }
            radio.set_channel(channel);
            radio.set_phy(self.phy);
            radio.set_tx_power(tx_power(for_phy_mut(&mut self.power, self.tx_phy).level()));
            self.stats.events = self.stats.events.wrapping_add(1);
            let encrypted = self.encryption.rx_on;
            let heard_before = self.listening();
            if let Some(address) = self.exchange(radio, clock, rx, window, shared) {
                self.exchanged(address);
            } else {
                self.note_miss(channel, window);
            }
            self.listened(heard_before);
            if self.counter == 0 {
                log_radio(radio);
            }
            self.process(rx, encrypted, shared);
            if let Some(ended) = self.ended(clock.now()) {
                break ended;
            }
            if reached(clock.now(), self.report_at) {
                self.report((clock.late(), clock.lead()));
            }
            self.counter = self.counter.wrapping_add(1);
        };
        self.finish(radio);
        (ended, self.stats)
    }

    /// Drives host information requests independently of link encryption.
    fn service_queries(&mut self, now: u32, shared: &Shared) {
        if self.notifications.iter().any(Option::is_some) {
            return;
        }
        self.host_queries |= shared.take_queries();
        if !matches!(self.phy_request, Request::Requested(_))
            && self.phy_update.is_none()
            && let Some(preferences) = shared.take_phy_request()
        {
            self.host_phy = Some(preferences);
            self.preferred_phys = preferences;
            self.phy_request = Request::NotStarted;
        }
        if let Some(status) = self.phy_status.take() {
            self.notify(Event::PhyUpdated { rx: self.phy.hci(), status, tx: self.tx_phy.hci() }, shared);
            self.host_phy = None;
            shared.complete_query(QUERY_PHY);
        }
        if let Some(error) = self.feature_error.take() {
            self.notify(Event::RemoteFeatures { features: [0; 8], status: error }, shared);
            self.host_queries &= !QUERY_FEATURES;
            shared.complete_query(QUERY_FEATURES);
        }
        if self.host_queries & QUERY_FEATURES != 0 {
            if let Some(features) = self.central_features {
                self.notify(Event::RemoteFeatures { features, status: STATUS_SUCCESS }, shared);
                self.host_queries &= !QUERY_FEATURES;
                shared.complete_query(QUERY_FEATURES);
            } else if self.features_request == Request::Done {
                self.features_request = Request::NotStarted;
            } else {
                // The outstanding feature procedure will answer this query.
            }
        }
        if self.host_queries & QUERY_VERSION != 0 {
            if let Some(version) = self.version {
                self.notify(Event::RemoteVersion(version), shared);
                self.host_queries &= !QUERY_VERSION;
                shared.complete_query(QUERY_VERSION);
            } else if self.version_request == Request::NotStarted
                && self.encryption.phase == Phase::Idle
                && self.queue.is_empty()
            {
                let mut version = [OP_VERSION_IND, 0, 0, 0, 0, 0];
                if let Some(bytes) = version.get_mut(1..) {
                    bytes.copy_from_slice(&VERSION);
                }
                self.enqueue(Llid::Control, &version);
                self.version_request = Request::Requested(now.wrapping_add(PROCEDURE_TIMEOUT_US));
            } else {
                // Wait for encryption or the outstanding version response.
            }
        }
        if matches!(self.version_request, Request::Requested(deadline) if reached(now, deadline)) {
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
        }
    }

    /// Applies the default PHY preference when establishing a new link.
    pub(crate) const fn set_preferred_phys(&mut self, preferences: [u8; 2]) { self.preferred_phys = preferences; }

    /// Applies the host's suggested data length when establishing a new
    /// link: the longest payload and time this side may send.
    pub(crate) const fn set_suggested_length(&mut self, length: [u16; 2]) { self.length = DataLength::new(length); }

    /// Passes the events from the current one up to `to` without listening,
    /// as the loop does one at a time: the current event's channel and
    /// instants were taken at the loop top, every further one's here.
    fn skip_to(&mut self, to: u16, shared: &Shared) {
        while self.counter != to {
            self.skipped = self.skipped.saturating_add(1);
            self.stats.skipped = self.stats.skipped.wrapping_add(1);
            self.counter = self.counter.wrapping_add(1);
            if self.counter != to {
                self.apply_instants(shared);
                _ = self.hopping.channel(&self.map, self.counter);
            }
        }
    }

    /// Whether the run loop skips the current event at `now`: while the
    /// peripheral latency leaves events to skip and nothing needs this one
    /// ([`Self::can_skip`]).
    #[inline]
    fn skips(&self, now: u32, shared: &Shared) -> bool { self.skipped < self.latency && self.can_skip(now, shared) }

    /// Slot `second` or the first.
    const fn slot(&self, second: bool) -> &TxSlot { if second { &self.slots.1 } else { &self.slots.0 } }

    /// Slot `second` or the first.
    const fn slot_mut(&mut self, second: bool) -> &mut TxSlot {
        if second { &mut self.slots.1 } else { &mut self.slots.0 }
    }

    /// Answers an encryption request: sends the peripheral's session key
    /// diversifier and IV and asks the host for the long term key.
    fn start_encryption(&mut self, params: &[u8]) {
        let (Some(rand), Some(ediv), Some(central_skd), Some(central_iv)) =
            (field::<8>(params, 0), field::<2>(params, 8), field::<8>(params, 10), field::<4>(params, 18))
        else {
            self.enqueue(Llid::Control, &[OP_REJECT_IND, ERROR_UNSUPPORTED_FEATURE]);
            return;
        };
        crypto::wipe(&mut self.encryption.skd);
        crypto::wipe(&mut self.encryption.iv);
        if let Some(target) = self.encryption.skd.get_mut(..8) {
            target.copy_from_slice(&central_skd);
        }
        if let Some(target) = self.encryption.iv.get_mut(..4) {
            target.copy_from_slice(&central_iv);
        }
        self.encryption.phase = Phase::AwaitingEntropy(KeyLookup { ediv, rand });
    }

    /// Starts the procedures of this side while no other runs: once the link
    /// is encrypted the feature exchange, then asking for LE 2M, and at any
    /// time the host's connection parameter requests, which would otherwise
    /// wait forever on a link that is never encrypted. Gives up on a central
    /// that does not answer in time.
    #[inline(never)]
    fn start_procedures(&mut self, now: u32, shared: &Shared) {
        shared.set_remote_features(self.central_features.map_or(0, |[first, ..]| first));
        self.announce_power();
        self.check_payload(now, shared);
        if [self.param_request, self.ping_request, self.remote_update]
            .into_iter()
            .flatten()
            .any(|deadline| reached(now, deadline))
        {
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
            return;
        }
        if [self.features_request, self.phy_request, self.length_request]
            .iter()
            .any(|request| matches!(request, Request::Requested(deadline) if reached(now, *deadline)))
        {
            self.abort = Some(ERROR_RESPONSE_TIMEOUT);
            return;
        }
        let idle = self.encryption.phase == Phase::Idle
            && self.param_update.is_none()
            && self.phy_update.is_none()
            && self.channel_update.is_none()
            && self.queue.is_empty()
            && self.notifications.iter().all(Option::is_none)
            && self.remote_request.is_none()
            && self.remote_update.is_none();
        let ours_running = [self.features_request, self.phy_request, self.length_request]
            .iter()
            .any(|request| matches!(request, Request::Requested(_)))
            || self.param_request.is_some();
        if !idle || ours_running {
            return;
        }
        let deadline = now.wrapping_add(PROCEDURE_TIMEOUT_US);
        let encrypted = self.encryption.tx_on;
        if (encrypted || self.host_queries & 1 != 0)
            && self.features_request == Request::NotStarted
            && self.central_features.is_none()
        {
            let mut request = [OP_PERIPHERAL_FEATURE_REQ, 0, 0, 0, 0, 0, 0, 0, 0];
            for (target, source) in request.iter_mut().skip(1).zip(FEATURES) {
                *target = source;
            }
            self.enqueue(Llid::Control, &request);
            self.features_request = Request::Requested(deadline);
        } else if (self.host_phy.is_some() || (chip::PHY_2M && encrypted && self.phy == Phy::M1))
            && self.phy_request == Request::NotStarted
        {
            if chip::PHY_2M {
                let [tx, rx] = self.preferred_phys;
                self.enqueue(Llid::Control, &[OP_PHY_REQ, tx, rx]);
                self.phy_request = Request::Requested(deadline);
            } else {
                // With LE 1M alone there is no PHY update procedure: the
                // host's request completes at once, on LE 1M.
                self.phy_request = Request::Done;
                self.phy_status = Some(STATUS_SUCCESS);
            }
        } else if self.length.local_tx != self.length.announced_tx
            && !self.length.unsupported
            && self.central_features.is_none_or(|[first, ..]| first & FEATURE_DATA_LENGTH != 0)
        {
            // The host changed what this side may send: the central learns
            // it, and of the longest this side receives. Unknown features
            // count as supported, as in Zephyr; an unknown response ends it.
            let request = self.length.pdu(OP_LENGTH_REQ);
            self.enqueue(Llid::Control, &request);
            self.length_request = Request::Requested(deadline);
        } else if let Some([min, max, latency, timeout]) = shared.take_param_request() {
            let current = self.current_params();
            if (min..=max).contains(&current.interval) && latency == current.latency && timeout == current.timeout {
                // Already in place: report success without a procedure.
                self.param_status = Some(STATUS_SUCCESS);
                return;
            }
            let mut request: [u8; 24] = [0; 24];
            let fields = [
                [OP_CONNECTION_PARAM_REQ].as_slice(),
                &le16_bytes(min),
                &le16_bytes(max),
                &le16_bytes(latency),
                &le16_bytes(timeout),
                // No preferred periodicity; offsets relative to this event.
                &[0],
                &le16_bytes(self.counter),
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
                &NO_OFFSET,
            ];
            for (target, source) in request.iter_mut().zip(fields.into_iter().flatten()) {
                *target = *source;
            }
            self.enqueue(Llid::Control, &request);
            self.param_request = Some(deadline);
            info!("asking for connection parameters");
        } else {
            // Nothing of ours to start.
        }
    }

    /// Starts the slots of a new link: an empty PDU on the air, and the
    /// first PDU to send in its place, as the link's first answer.
    fn start_slots(&mut self, shared: &Shared) {
        self.slots = (TxSlot::empty(), TxSlot::empty());
        self.cur = false;
        self.tx_kind = TxKind::Empty;
        self.prepare_next(shared);
        if self.next_ready {
            self.commit_next();
        }
    }

    /// Counts the new packet just accepted: passes data in plain text to the
    /// host at once, and keeps a control PDU for [`Self::process`] after the
    /// event. Its CCM counter is used up at once, as the next packet of the
    /// event may be decrypted before then.
    fn stash(&mut self, rx: &[u8; BUFFER_LEN], encrypted: bool, shared: &Shared) {
        self.seq.received = false;
        self.stats.received = self.stats.received.wrapping_add(1);
        // A payload, encrypted or not, holds the latency off for a while.
        if rx.get(1).is_some_and(|&len| len != 0) {
            self.hold_latency_from(self.last_valid);
        }
        // Empty PDUs have no MIC and need not produce a CCM output packet.
        let source = if encrypted && rx.get(1) != Some(&0) { self.rx_plain.as_slice() } else { rx.as_slice() };
        let header = source.first().copied().unwrap_or_default();
        let len = source.get(1).copied().unwrap_or_default();
        if encrypted && len != 0 {
            self.encryption.rx_counter = self.encryption.rx_counter.saturating_add(1);
        }
        if len != 0 || header & MD != 0 {
            self.skipped = self.latency;
        }
        if len == 0 {
            return;
        }
        let payload = source.get(DATA_HEADER_LEN..DATA_HEADER_LEN.saturating_add(usize::from(len))).unwrap_or_default();
        if header & LLID_MASK == Llid::Control.bits() {
            // Copied straight into its slot: the link layer interrupt keeps
            // no packet copy on its stack.
            if let Some(held) = self.pending.push_mut() {
                held.encrypted = encrypted;
                held.bytes.fill(0);
                for (target, &byte) in held.bytes.iter_mut().zip(source) {
                    *target = byte;
                }
            }
        } else {
            // Data goes to the host at once, in order: a control PDU closes
            // the event, so no data follows one that waits. `receive` made
            // sure of the room.
            let kind = if header & LLID_MASK == Llid::Start.bits() { Llid::Start } else { Llid::Continuation };
            _ = shared.push_acl_in(kind, payload, encrypted);
        }
    }

    /// Longest payload this side may send now: the effective octets, and as
    /// many as fit the effective time on the transmit PHY with the MIC.
    const fn tx_payload_max(&self) -> usize {
        let [octets, time, ..] = self.length.effective();
        let per_byte = u32::checked_div(8, u32::from(self.tx_phy.hci())).unwrap_or(8);
        let mic = if self.encryption.tx_on { MIC_LEN } else { 0 };
        // Preamble and access address, header and CRC.
        let overhead = self.tx_phy.address_offset_us().checked_div(per_byte).unwrap_or(0).saturating_add(5);
        let by_time = u32::from(time).checked_div(per_byte).unwrap_or(0).saturating_sub(overhead);
        by_time.saturating_cast::<usize>().saturating_sub(mic).min(usize::from(octets)).min(ACL_MAX)
    }

    /// Sleeps until an access address arrives or `deadline` passes, woken by
    /// a timer compare instead of polling. Returns whether one arrived.
    fn wait_address(radio: &mut Radio<'_>, clock: &Clock<'_>, deadline: u32) -> bool {
        clock.expire_at(deadline);
        let heard = radio.wait_address(|| clock.expired(deadline));
        clock.stop_expiry();
        heard
    }

    /// Window widening after `elapsed` microseconds since the last anchor,
    /// at most half the interval less the interframe space (Core, Vol 6,
    /// Part B, 4.5.7), as Zephyr limits it: wider windows would overlap the
    /// neighbouring events.
    const fn widening(&self, elapsed: u32) -> u32 {
        let drift = u64::from(elapsed).saturating_mul(u64::from(self.sca_ppm)).div_ceil(1_000_000);
        let limit = self.interval.wrapping_shr(1).saturating_sub(T_IFS_US);
        drift.saturating_cast::<u32>().saturating_add(WIDENING_FIXED_US).min(limit)
    }

    /// Radio start and access address deadline of the current event.
    const fn window(&self) -> (u32, u32) { self.window_at(self.counter) }

    /// Radio start and access address deadline of event `counter`.
    const fn window_at(&self, counter: u16) -> (u32, u32) {
        let (earliest, latest) = match self.expect {
            Expect::Anchor => {
                let expected = self
                    .anchor
                    .wrapping_add(self.interval.wrapping_mul(u32::from(counter.wrapping_sub(self.anchor_counter))));
                (expected, expected)
            },
            Expect::Window { start, size } => {
                let earliest = start.wrapping_add(self.phy.address_offset_us());
                (earliest, earliest.wrapping_add(size))
            },
        };
        let widening = self.widening(latest.wrapping_sub(self.anchor));
        let enable = earliest
            .wrapping_sub(widening)
            .wrapping_sub(self.phy.address_offset_us())
            .wrapping_sub(RAMP_UP_US)
            .wrapping_sub(RX_MARGIN_US);
        (enable, latest.wrapping_add(widening).wrapping_add(RX_TAIL_US))
    }
}

/// How long before the radio's start of an event the host's data has to be
/// queued to go out at it, with the crystal starting `crystal_lead`
/// microseconds before TIMER0 restarts for the event. Where the chip
/// prepares again after the restart ([`chip::PREPARE_AFTER_RESTART`]),
/// until the restart, which may come an RTC tick early. Elsewhere until the
/// crystal starts, after which the sleep no longer listens for the host,
/// and at least as long before as [`Connection::prepare_after_wake`] needs.
#[cfg(feature = "event-timing")]
const fn queue_lead(crystal_lead: u32) -> u32 {
    let restart = SETUP_US.saturating_add(RESTART_EARLY_US);
    if chip::PREPARE_AFTER_RESTART {
        return restart;
    }
    let crystal = restart.saturating_add(crystal_lead);
    let wake = SETUP_US.saturating_add(PREPARE_AGAIN_US);
    crystal.max(wake)
}

/// Parses the parameters of a connection update.
const fn parse_update(bytes: &[u8]) -> Option<Update> {
    let [win_size, offset0, offset1, interval0, interval1, latency0, latency1, timeout0, timeout1, instant0, instant1] =
        field::<11>(bytes, 0)?;
    let params =
        ConnectionParams::new(le16([interval0, interval1]), le16([latency0, latency1]), le16([timeout0, timeout1]));
    if !valid_connection_parameters(params.interval, params.latency, params.timeout, win_size, le16([offset0, offset1]))
    {
        return None;
    }
    Some(Update {
        instant: le16([instant0, instant1]),
        interval: u32::from(le16([interval0, interval1])).saturating_mul(UNIT_1250_US),
        latency: params.latency,
        params,
        requested: false,
        timeout: u32::from(le16([timeout0, timeout1])).saturating_mul(UNIT_10MS_US),
        win_offset: u32::from(le16([offset0, offset1])).saturating_mul(UNIT_1250_US),
        win_size: u32::from(win_size).saturating_mul(UNIT_1250_US),
    })
}

/// Logs the radio's packet layout, interframe space and whitening once per
/// link, which rules out its set-up on real hardware.
fn log_radio(radio: &Radio<'_>) {
    if cfg!(feature = "defmt") {
        let [pcnf0, pcnf1, tifs, whitening] = radio.registers();
        info!(
            "radio: PCNF0 {=u32:#010x}, PCNF1 {=u32:#010x}, TIFS {} us, DATAWHITEIV {=u32:#04x}, state {}",
            pcnf0,
            pcnf1,
            tifs,
            whitening,
            radio.state()
        );
    }
}

/// Selects per-PHY state without indexing or a fallible conversion.
const fn for_phy_mut<Value>(values: &mut [Value; 2], phy: Phy) -> &mut Value {
    let &mut [ref mut one, ref mut two] = values;
    match phy {
        Phy::M1 => one,
        Phy::M2 => two,
    }
}

/// Transmit power in dBm of power control level `level`.
const fn tx_power(level: usize) -> i8 { LEVELS_DBM.get(level).copied().unwrap_or_default() }

/// Whether an instant is still ahead of the current event: the event at it
/// is running already, and the specification counts a distance of 32767 or
/// more as passed.
const fn future_instant(now: u16, instant: u16) -> bool {
    let distance = instant.wrapping_sub(now);
    distance != 0 && distance < 0x7FFF
}

/// Exact parameter lengths of the control PDUs this controller understands.
const fn control_len(code: u8) -> Option<usize> {
    match code {
        OP_CONNECTION_UPDATE_IND => Some(11),
        OP_CHANNEL_MAP_IND => Some(7),
        OP_TERMINATE_IND | OP_UNKNOWN_RSP | OP_REJECT_IND => Some(1),
        OP_ENC_REQ => Some(22),
        OP_ENC_RSP => Some(12),
        OP_START_ENC_REQ | OP_START_ENC_RSP | OP_PAUSE_ENC_REQ | OP_PAUSE_ENC_RSP | OP_PING_REQ | OP_PING_RSP => {
            Some(0)
        },
        OP_FEATURE_REQ | OP_FEATURE_RSP | OP_PERIPHERAL_FEATURE_REQ | OP_LENGTH_REQ | OP_LENGTH_RSP => Some(8),
        OP_VERSION_IND => Some(5),
        OP_PHY_REQ | OP_PHY_RSP | OP_REJECT_EXT_IND => Some(2),
        OP_CONNECTION_PARAM_REQ | OP_CONNECTION_PARAM_RSP => Some(23),
        OP_PHY_UPDATE_IND | OP_POWER_CONTROL_RSP | OP_POWER_CHANGE_IND => Some(4),
        OP_POWER_CONTROL_REQ => Some(3),
        _ => None,
    }
}

/// Power control flags of `level`: bit 0 at the lowest power, bit 1 at the
/// highest.
const fn limit_flags(level: usize) -> u8 {
    u8::from(level == 0) | u8::from(level.saturating_add(1) >= LEVELS_DBM.len()).wrapping_shl(1)
}

/// Whether a connection parameter request or response has parameters within
/// the specification: an interval range, latency and supervision timeout.
const fn valid_request(params: &[u8]) -> bool {
    let Some([min0, min1, max0, max1, latency0, latency1, timeout0, timeout1]) = field::<8>(params, 0) else {
        return false;
    };
    let min = le16([min0, min1]);
    let max = le16([max0, max1]);
    min <= max
        && valid_connection_parameters(min, le16([latency0, latency1]), le16([timeout0, timeout1]), 1, 0)
        && valid_connection_parameters(max, le16([latency0, latency1]), le16([timeout0, timeout1]), 1, 0)
}

#[cfg(test)] mod tests;
