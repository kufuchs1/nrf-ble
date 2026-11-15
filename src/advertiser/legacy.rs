//! Legacy advertising: the five advertising types, scan responses and their
//! advertising event on the primary channels.

use super::{CHANNELS, LISTEN_US, Settings};
use crate::{
    clock::Clock,
    pdu::{
        ADV_ACCESS_ADDRESS,
        ADV_CRC_INIT,
        ADV_IND,
        ADV_NONCONN_IND,
        ADV_SCAN_IND,
        BUFFER_LEN,
        ConnectInd,
        LegacyAdvertisement,
        Peer,
        SCAN_RSP,
        is_scan_request,
        scan_request,
    },
    radio::{Radio, Turnaround},
};
use core::sync::atomic::{AtomicU32, Ordering};

/// Largest advertising data.
pub const DATA_MAX: usize = 31;
/// Largest scan response data.
pub const SCAN_DATA_MAX: usize = 31;
/// Scan requests decided only after the radio had started sending the scan
/// response. Only the link layer task writes it.
static LATE_SCAN_DECISIONS: AtomicU32 = AtomicU32::new(0);

/// The advertiser's counters as last logged.
pub struct Counters {
    /// Scan requests decided late, see [`late_scan_decisions`].
    late_scans: u32,
}

impl Counters {
    /// Logs the scan requests the advertiser decided only after the radio
    /// had started sending the scan response, when there are more than at
    /// the last call.
    #[inline]
    pub fn log(&mut self) {
        let late = late_scan_decisions();
        if late != self.late_scans {
            self.late_scans = late;
            info!("advertising: {} scan requests decided late", late);
        }
    }

    /// No counts logged yet.
    #[inline]
    #[must_use = "the counters are only created"]
    pub const fn new() -> Self { Self { late_scans: 0 } }
}

impl Default for Counters {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Advertising type.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
#[non_exhaustive]
pub enum Kind {
    /// Connectable and scannable undirected.
    ConnectableUndirected,
    /// Connectable directed, high duty cycle.
    DirectedHighDuty,
    /// Connectable directed, low duty cycle.
    DirectedLowDuty,
    /// Non-connectable and non-scannable undirected.
    NonConnectable,
    /// Scannable undirected.
    Scannable,
}

impl Kind {
    /// The type for an HCI advertising type value.
    #[inline]
    #[must_use = "the type is only decoded"]
    pub const fn from_hci(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ConnectableUndirected),
            1 => Some(Self::DirectedHighDuty),
            2 => Some(Self::Scannable),
            3 => Some(Self::NonConnectable),
            4 => Some(Self::DirectedLowDuty),
            _ => None,
        }
    }

    /// Whether a central may connect.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_connectable(self) -> bool {
        matches!(self, Self::ConnectableUndirected | Self::DirectedHighDuty | Self::DirectedLowDuty)
    }

    /// Whether the advertising is directed.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_directed(self) -> bool { matches!(self, Self::DirectedHighDuty | Self::DirectedLowDuty) }

    /// Whether the advertising is high duty cycle directed, which runs its
    /// events back to back for at most 1.28 s.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_high_duty(self) -> bool { matches!(self, Self::DirectedHighDuty) }
}

/// Whether a scanner gets a scan response. With the filter accept list, a
/// resolvable private address counts as the identity it resolves to. This
/// runs within the interframe space: resolving takes one AES block of about
/// 7 us per listed peer, and only for an address of the resolvable type that
/// is not listed itself.
fn accepts_scan(settings: &Settings, scanner: Peer) -> bool {
    if settings.resolution_enabled && !settings.resolving.accepts_identity(scanner) {
        return false;
    }
    matches!(settings.kind, Kind::ConnectableUndirected | Kind::Scannable)
        && (settings.filter_policy & 0x01 == 0
            || settings.filter.contains(scanner)
            || settings.resolve(scanner).is_some_and(|identity| settings.filter.contains(identity)))
}

/// Runs one advertising event on the enabled channels. Returns a valid
/// connection request and the time its packet ended.
#[inline]
pub fn event(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    pdus: (&LegacyAdvertisement, &LegacyAdvertisement),
    rx: &mut [u8; BUFFER_LEN],
) -> Option<(ConnectInd, u32)> {
    radio.set_access_address(ADV_ACCESS_ADDRESS);
    radio.set_crc_init(ADV_CRC_INIT);
    CHANNELS
        .into_iter()
        .filter(|&(_, bit)| settings.channel_map & bit != 0)
        .find_map(|(channel, _)| on_channel(radio, clock, settings, pdus, rx, channel))
}

/// Scan requests decided only after the radio had started sending the scan
/// response: sent to a scanner the filter accept list refuses, or cut short
/// by the decision to refuse it.
#[inline]
#[must_use = "the count is only read"]
pub fn late_scan_decisions() -> u32 { LATE_SCAN_DECISIONS.load(Ordering::Relaxed) }

/// Sends the advertisement on one channel and serves a request that follows.
///
/// The scan request checks run within the interframe space, with up to two
/// address resolutions on the ECB for the filter accept list, which may not
/// fit on the 16 MHz Cortex-M0. So once the request's access address came,
/// the radio points at the scan response, and anything but a scan request
/// stops the turnaround at once: a late decision sends the scan response,
/// never the request back (see [`late_scan_decisions`]).
fn on_channel(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    (advertisement, scan_response): (&LegacyAdvertisement, &LegacyAdvertisement),
    rx: &mut [u8; BUFFER_LEN],
    channel: u8,
) -> Option<(ConnectInd, u32)> {
    radio.set_channel(channel);
    let listen = settings.kind != Kind::NonConnectable;
    let after = if listen { Turnaround::Receive } else { Turnaround::None };
    // SAFETY: the radio only reads the advertisement, which is borrowed for
    // this event; every path out waits until the radio is disabled.
    unsafe { radio.prepare(advertisement.as_bytes().as_ptr().cast_mut(), after) }
    radio.transmit();
    radio.wait_end();
    if !listen {
        radio.wait_disabled();
        return None;
    }
    // SAFETY: `rx` is a full packet buffer borrowed for this event; every
    // path out waits until the radio is disabled.
    unsafe { radio.set_buffer(rx.as_mut_ptr()) }
    radio.wait_switched();
    radio.set_turnaround(Turnaround::Transmit);
    radio.clear_address();
    let deadline = clock.end_time().wrapping_add(LISTEN_US);
    clock.expire_at(deadline);
    let heard = radio.wait_address(|| clock.expired(deadline));
    clock.stop_expiry();
    if !heard {
        radio.disable();
        return None;
    }
    // The reception latched `rx`: the pointer now applies to the answer.
    // SAFETY: the radio only reads the scan response, borrowed for this
    // event, and is disabled before it returns.
    unsafe { radio.set_buffer(scan_response.as_bytes().as_ptr().cast_mut()) }
    radio.clear_ready();
    radio.wait_end();
    let end = clock.end_time();
    let valid = radio.crc_ok();
    if valid && is_scan_request(rx[0]) {
        let answer = scan_request(rx, settings.own).is_some_and(|scanner| accepts_scan(settings, scanner));
        if radio.tx_started() {
            LATE_SCAN_DECISIONS.store(late_scan_decisions().wrapping_add(1), Ordering::Relaxed);
        }
        if answer {
            radio.wait_switched();
            radio.set_turnaround(Turnaround::None);
            radio.wait_end();
            radio.wait_disabled();
            return None;
        }
        radio.disable();
        return None;
    }
    // The switch would answer the packet: it is stopped before.
    radio.disable();
    if !valid {
        return None;
    }
    ConnectInd::parse(rx, settings.own)
        .filter(|request| settings.accepts_connection(request.central()))
        .map(|request| (request, end))
}

/// The advertising PDU and the scan response of `settings`.
#[inline]
#[must_use = "the PDUs are only built"]
pub fn pdus(settings: &Settings) -> (LegacyAdvertisement, LegacyAdvertisement) {
    let data = settings.data.get(..usize::from(settings.len)).unwrap_or_default();
    let scan_data = settings.scan_data.get(..usize::from(settings.scan_len)).unwrap_or_default();
    let primary = match settings.kind {
        Kind::ConnectableUndirected => LegacyAdvertisement::undirected(ADV_IND, settings.own, data),
        Kind::DirectedHighDuty | Kind::DirectedLowDuty => {
            LegacyAdvertisement::directed(settings.own, settings.target())
        },
        Kind::NonConnectable => LegacyAdvertisement::undirected(ADV_NONCONN_IND, settings.own, data),
        Kind::Scannable => LegacyAdvertisement::undirected(ADV_SCAN_IND, settings.own, data),
    };
    (primary, LegacyAdvertisement::undirected(SCAN_RSP, settings.own, scan_data))
}

/// Sets the advertising data and the scan response data of `settings`.
/// Returns false, changing neither, if one is longer than [`DATA_MAX`] or
/// [`SCAN_DATA_MAX`].
#[inline]
#[must_use = "data that does not fit is refused"]
pub fn set_data(settings: &mut Settings, adv: &[u8], scan: &[u8]) -> bool {
    if adv.len() > DATA_MAX || scan.len() > SCAN_DATA_MAX {
        return false;
    }
    for (target, len, source) in
        [(&mut settings.data, &mut settings.len, adv), (&mut settings.scan_data, &mut settings.scan_len, scan)]
    {
        target.fill(0);
        if let Some(destination) = target.get_mut(..source.len()) {
            destination.copy_from_slice(source);
        }
        *len = source.len().saturating_cast();
    }
    true
}

#[cfg(test)] mod tests;
