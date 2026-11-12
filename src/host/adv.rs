//! Connectable advertising and the advertising data writer.
//!
//! [`Data`] writes advertising and scan response data, AD structures of
//! [`DATA_MAX`] octets at most: flags, the complete or shortened local name,
//! the appearance, the complete list of 16-bit service UUIDs and the TX power
//! level. A structure that does not fit is refused with [`Overflow`] and
//! leaves the data as it was. [`Content`] builds both sets of a device from its
//! name, appearance and services, which the device defines
//! ([`Content::new`]).
//!
//! # Modes
//!
//! A device advertises in one of two [`Mode`]s, connectable and
//! undirected in both, and always from a resolvable private address made with
//! its own identity resolving key, which the link layer renews every
//! [`RPA_TIMEOUT_S`] seconds:
//!
//! - [`Mode::Pairing`]: discoverable (LE General Discoverable) with the name,
//!   and any central may connect and pair. The address lives 900 s, as
//!   `bluetoothctl pair` waits for advertising from the exact address it
//!   scanned.
//! - [`Mode::Reconnect`]: only the bonded central may connect, not discoverable
//!   and without the name. The central's identity is the only entry of the
//!   filter accept list and of the resolving list, with its key if it sent one,
//!   and the link layer resolves its resolvable private addresses through that
//!   list: scan requests and connection requests from any other device are
//!   ignored. The entry is in device privacy mode, so the central may also
//!   connect from its identity address, as `BlueZ` does without host privacy.
//!
//! With the feature `directed-advertising`, a phase in [`Mode::Reconnect`]
//! may also be directed (`Phase::directed`): high duty cycle directed
//! advertising, an `ADV_DIRECT_IND` to the bonded central every 3.75 ms for
//! at most `DIRECTED_MAX`, connectable by that central only. Linux connects
//! to it as to an undirected advertisement from a device of its accept list
//! with auto-connect (and only to it for a device `BlueZ` merely allows to
//! connect), so a first directed phase makes a reconnection about 30 to 50 ms
//! faster than one at 20 ms. The target is the central's identity address,
//! which a central scanning from its identity address takes: Linux without
//! host privacy, which sends no identity resolving key at pairing. A central
//! that sent one scans from resolvable private addresses (Linux with
//! `Privacy = device`) and would drop an advertisement directed to its
//! identity, so its bond is not directed to. Where a directed phase cannot be
//! directed, in pairing mode, for a bond with the central's key and for one
//! whose central has no identity address, public or static random, as right
//! after pairing with a central that sent none (`Mode::directs`), it
//! advertises undirected at 20 ms instead, for the same time. It is the
//! firmware's choice, opt-in through the feature and its reconnection
//! schedule.
//!
//! [`Advertising::configure`] sets the link layer up for a mode once, while it
//! does not advertise: our identity address
//! ([`crate::link::Link::set_identity`]), the resolving list
//! ([`crate::link::Link::add_peer`]), the filter accept list and address
//! resolution. [`Advertising::start`] then advertises with the interval of a
//! [`Phase`] ([`crate::link::Link::advertise`]), again for each phase: the
//! private address stays the same across them.
//!
//! # Phases
//!
//! A [`Schedule`] is data: the phases of advertising, each an interval and how
//! long it lasts, and the time a connection gets to become encrypted. The
//! device defines one for each mode and passes it to [`Advertising::new`]
//! with its [`Content`]. A remote for instance advertises at 20 ms for 3 s,
//! so a central that waits connects at once, then at 50 ms for 12 s and at
//! 400 ms for 45 s, one minute in all, and gives 60 s to pair and 20 s for
//! the bonded central to encrypt, which it does at once:
//!
//! ```
//! use embassy_time::Duration;
//! use nrf_ble::host::adv::{
//!     Advertising,
//!     BATTERY_SERVICE,
//!     Content,
//!     HID_SERVICE,
//!     Mode,
//!     Overflow,
//!     Phase,
//!     Schedule,
//! };
//!
//! /// 20 ms for 3 s, 50 ms for 12 s, 400 ms for 45 s.
//! const PHASES: [Phase; 3] = [
//!     Phase::new(32, Duration::from_secs(3)),
//!     Phase::new(80, Duration::from_secs(12)),
//!     Phase::new(640, Duration::from_secs(45)),
//! ];
//! /// Pairing: 60 s to pair.
//! const PAIRING: Schedule = Schedule::new(&PHASES, Duration::from_secs(60));
//! /// Reconnection: 20 s for the bonded central to encrypt.
//! const RECONNECT: Schedule = Schedule::new(&PHASES, Duration::from_secs(20));
//! /// The name, a keyboard's appearance, the HID and Battery services.
//! const CONTENT: Content<'static> =
//!     Content::new(b"My Remote", 0x03C1, &[HID_SERVICE, BATTERY_SERVICE]);
//!
//! /// The advertising of `mode`.
//! fn advertising(mode: Mode<'_>) -> Result<Advertising<'_>, Overflow> {
//!     let schedule = if mode.pairable() { &PAIRING } else { &RECONNECT };
//!     Advertising::new(mode, schedule, &CONTENT)
//! }
//!
//! let pairing = advertising(Mode::Pairing).unwrap();
//! assert_eq!(pairing.scan().as_bytes(), b"");
//! assert_eq!(&pairing.data().as_bytes()[13..], b"\x0A\x09My Remote");
//! ```
//!
//! # The advertising call
//!
//! [`crate::host::Host::advertise`] builds on these: in pairing mode it
//! waits for the P-256 key pair of the next pairing before it calls
//! [`Advertising::start`], so a reconnection never computes one, then runs
//! the phases until a central connects. A central that connects after the
//! call's future was dropped is kept for the next call or disconnected with
//! reason 0x13, as [`crate::host::engine::Unclaimed`] says.

use crate::{
    advertiser::legacy::{self, Kind},
    bytes::le16_bytes,
    host::{bond::Bond, identity::LocalIdentity},
    link::{self, AdvParams, Link},
    pdu::Peer,
};
use embassy_time::Duration;

/// Largest advertising or scan response data.
pub const DATA_MAX: usize = legacy::DATA_MAX;
/// AD type: flags.
pub const AD_FLAGS: u8 = 0x01;
/// AD type: the complete list of 16-bit service UUIDs.
pub const AD_SERVICES_16: u8 = 0x03;
/// AD type: the shortened local name.
pub const AD_SHORT_NAME: u8 = 0x08;
/// AD type: the complete local name.
pub const AD_NAME: u8 = 0x09;
/// AD type: the TX power level.
pub const AD_TX_POWER: u8 = 0x0A;
/// AD type: the appearance.
pub const AD_APPEARANCE: u8 = 0x19;
/// The longest a directed phase lasts: the link layer ends high duty cycle
/// directed advertising after 1.28 s.
#[cfg(feature = "directed-advertising")]
pub const DIRECTED_MAX: Duration = Duration::from_millis(1280);
/// The interval of a directed phase where it cannot be directed: 20 ms.
///
/// In units of 0.625 ms, for the undirected advertising that takes its place;
/// the link layer keeps its own for directed advertising, 3.75 ms.
#[cfg(feature = "directed-advertising")]
pub const DIRECTED_FALLBACK: u16 = 32;
/// Flag: LE General Discoverable Mode.
pub const LE_GENERAL_DISCOVERABLE: u8 = 0x02;
/// Flag: BR/EDR not supported.
pub const BR_EDR_NOT_SUPPORTED: u8 = 0x04;
/// The HID service.
pub const HID_SERVICE: u16 = 0x1812;
/// The Battery service.
pub const BATTERY_SERVICE: u16 = 0x180F;
/// Lifetime of our resolvable private address in seconds: 900, the
/// specification's suggestion and the least that pairing with
/// `bluetoothctl pair` allows.
pub const RPA_TIMEOUT_S: u16 = 900;
/// Filter policy of [`Mode::Reconnect`]: scan and connection requests only
/// from the filter accept list.
const FILTER_BONDED: u8 = 0x03;
/// The two most significant bits of a static random address.
#[cfg(feature = "directed-advertising")]
const STATIC_RANDOM: u8 = 0xC0;
/// The identity of the resolving list entry that only carries our own key
/// in [`Mode::Pairing`]: no central has this address.
const NO_PEER: Peer = Peer::new([0; 6], false);

/// One mode's advertising: the mode, its schedule, and the advertising and
/// scan response data.
pub struct Advertising<'bond> {
    /// The advertising data.
    data:     Data,
    /// The mode.
    mode:     Mode<'bond>,
    /// The scan response data.
    scan:     Data,
    /// The phases and the security deadline.
    schedule: &'static Schedule,
}

/// What a device advertises: its name, appearance, services and,
/// optionally, its TX power level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Content<'name> {
    /// The appearance (Assigned Numbers, 2.6).
    pub appearance: u16,
    /// The complete local name, UTF-8.
    pub name:       &'name [u8],
    /// The 16-bit UUIDs of the services, in the order to list them.
    pub services:   &'name [u16],
    /// The TX power level in dBm, if it is to be advertised.
    pub tx_power:   Option<i8>,
}

/// Advertising or scan response data: AD structures, [`DATA_MAX`] octets at
/// most.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Data {
    /// The structures, of which the first `len` octets count.
    bytes: [u8; DATA_MAX],
    /// Their length.
    len:   u8,
}

/// Why advertising could not be set up or started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    /// The link layer refused a call.
    Link(link::Error),
    /// The bond of [`Mode::Reconnect`] was made under another identity than
    /// the one given: the central would not know our address.
    WrongIdentity,
}

/// How the device advertises.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Mode<'bond> {
    /// Discoverable, any central may connect and pair.
    Pairing,
    /// Only the bonded central may connect, and pairing is refused.
    Reconnect(&'bond Bond),
}

/// Why an AD structure was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Overflow {
    /// It does not fit in the [`DATA_MAX`] octets.
    TooLong,
}

/// One phase of advertising: its interval and how long it lasts, and with
/// the feature `directed-advertising` whether it is directed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Phase {
    /// Whether it is high duty cycle directed advertising to the bonded
    /// central ([`Self::directed`]), which takes its interval from the link
    /// layer: `interval` is then that of the undirected advertising that
    /// takes its place where it cannot be directed ([`Mode::directs`]).
    #[cfg(feature = "directed-advertising")]
    pub directed: bool,
    /// How long the phase lasts.
    pub duration: Duration,
    /// The advertising interval in units of 0.625 ms: 32 (20 ms) to 16384.
    pub interval: u16,
}

/// The phases of advertising in one mode and the time a connection gets to
/// become encrypted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Schedule {
    /// The phases in order. After the last one the device stops
    /// advertising, or keeps the last phase, as the firmware decides.
    pub phases:            &'static [Phase],
    /// The time from a connection until it must be encrypted; the host then
    /// disconnects with reason 0x05.
    pub security_deadline: Duration,
}

/// A call of the link layer that advertising makes, with its arguments.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Call<'data> {
    /// [`Link::accept_list_add`].
    AcceptListAdd(Peer),
    /// [`Link::accept_list_clear`].
    AcceptListClear,
    /// [`Link::add_peer`].
    AddPeer {
        /// The peer's identity.
        identity:  Peer,
        /// Our identity resolving key, least significant octet first.
        local_irk: [u8; 16],
        /// The peer's identity resolving key, least significant octet
        /// first, or zeros.
        peer_irk:  [u8; 16],
    },
    /// [`Link::advertise`].
    Advertise {
        /// The advertising data.
        adv:    &'data [u8],
        /// The parameters.
        params: AdvParams,
        /// The scan response data.
        scan:   &'data [u8],
    },
    /// [`Link::clear_peers`].
    ClearPeers,
    /// [`Link::set_address_resolution`].
    SetAddressResolution(bool),
    /// [`Link::set_identity`].
    SetIdentity([u8; 6]),
    /// [`Link::set_privacy_mode`].
    SetPrivacyMode {
        /// Device privacy rather than network privacy.
        device:   bool,
        /// The peer's identity.
        identity: Peer,
    },
    /// [`Link::set_rpa_timeout`].
    SetRpaTimeout(u16),
    /// [`Link::stop_advertising`], which cannot fail.
    StopAdvertising,
}

/// What advertising calls in the link layer: the firmware passes the
/// [`Link`], the host tests a stand-in that records the calls.
pub trait Control {
    /// Makes `call`.
    ///
    /// # Errors
    ///
    /// The link layer's, as the call documents it.
    fn call(&self, call: Call<'_>) -> Result<(), link::Error>;
}

impl<'bond> Advertising<'bond> {
    /// Sets the link layer up for the mode, stopping advertising first:
    /// `identity` as our identity address and, in the resolving list, our
    /// key; the bonded central in the filter accept list and the resolving
    /// list in [`Mode::Reconnect`], neither list holding a central
    /// otherwise; address resolution on only for [`Mode::Reconnect`]; and the
    /// lifetime of our private address. Call it before the first
    /// [`Self::start`] of the mode, while no central is connected.
    ///
    /// # Errors
    ///
    /// [`Error::WrongIdentity`] if the bond was made under another variant
    /// than `identity`'s, [`Error::Link`] if the link layer refused a call.
    #[inline]
    pub fn configure<C>(&self, control: &C, identity: &LocalIdentity) -> Result<(), Error>
    where
        C: Control,
    {
        if let Mode::Reconnect(bond) = self.mode
            && bond.local != identity.variant()
        {
            return Err(Error::WrongIdentity);
        }
        let (central, peer_irk) = match self.mode {
            Mode::Pairing => (None, [0; 16]),
            Mode::Reconnect(bond) => (Some(bond.peer), bond.peer_irk.unwrap_or_default()),
        };
        for call in [
            Call::StopAdvertising,
            Call::SetAddressResolution(false),
            Call::SetIdentity(identity.address()),
            Call::ClearPeers,
            Call::AcceptListClear,
            Call::AddPeer { identity: central.unwrap_or(NO_PEER), local_irk: identity.irk(), peer_irk },
        ] {
            control.call(call)?;
        }
        if let Some(peer) = central {
            for call in [
                Call::SetPrivacyMode { device: true, identity: peer },
                Call::AcceptListAdd(peer),
                Call::SetAddressResolution(true),
            ] {
                control.call(call)?;
            }
        }
        control.call(Call::SetRpaTimeout(RPA_TIMEOUT_S))?;
        Ok(())
    }

    /// The advertising data.
    #[inline]
    #[must_use = "the data is only read"]
    pub const fn data(&self) -> &Data { &self.data }

    /// The mode.
    #[inline]
    #[must_use = "the mode is only read"]
    pub const fn mode(&self) -> Mode<'bond> { self.mode }

    /// Advertising in `mode` on `schedule`, with the data of `content` for
    /// the mode ([`Content::data`]).
    ///
    /// # Errors
    ///
    /// [`Overflow`] if the content does not fit.
    #[inline]
    pub fn new(mode: Mode<'bond>, schedule: &'static Schedule, content: &Content<'_>) -> Result<Self, Overflow> {
        let (data, scan) = content.data(mode.discoverable())?;
        Ok(Self { data, mode, scan, schedule })
    }

    /// The scan response data.
    #[inline]
    #[must_use = "the data is only read"]
    pub const fn scan(&self) -> &Data { &self.scan }

    /// The phases and the security deadline.
    #[inline]
    #[must_use = "the schedule is only read"]
    pub const fn schedule(&self) -> &'static Schedule { self.schedule }

    /// Advertises with `phase`'s interval until a central connects, or
    /// until [`Link::stop_advertising`] or another call replaces it; a
    /// directed phase ends by itself after 1.28 s. The mode is to be
    /// [`Self::configure`]d first.
    ///
    /// # Errors
    ///
    /// [`Error::Link`] if the link layer refused: an interval out of range,
    /// a central connected, or no identity address.
    #[inline]
    pub fn start<C>(&self, control: &C, phase: &Phase) -> Result<(), Error>
    where
        C: Control,
    {
        let params = self.mode.params(phase);
        Ok(control.call(Call::Advertise { adv: self.data.as_bytes(), params, scan: self.scan.as_bytes() })?)
    }
}

impl<'name> Content<'name> {
    /// The advertising and the scan response data, `discoverable` or not.
    ///
    /// The advertising data holds the flags (LE General Discoverable only
    /// if `discoverable`, BR/EDR not supported), the services and the
    /// appearance, and if `discoverable` the name: complete if it fits,
    /// otherwise shortened at a character boundary to what fits, and then
    /// complete in the scan response. Without `discoverable` neither holds the
    /// name, so other devices do not list the device. The TX power level, if
    /// any, goes in the scan response.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if a structure does not fit, or not even one character
    /// of the name.
    #[inline]
    pub fn data(&self, discoverable: bool) -> Result<(Data, Data), Overflow> {
        let flags = if discoverable { LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED } else { BR_EDR_NOT_SUPPORTED };
        let mut adv = Data::new();
        adv.flags(flags)?.services(self.services)?.appearance(self.appearance)?;
        let mut scan = Data::new();
        if discoverable && adv.name_fitting(self.name)? {
            scan.name(self.name)?;
        }
        if let Some(dbm) = self.tx_power {
            scan.tx_power(dbm)?;
        }
        Ok((adv, scan))
    }

    /// The content of a device named `name` (its complete local name, UTF-8,
    /// as its Device Name characteristic holds it) with `appearance` (the
    /// value of its Appearance characteristic) and the 16-bit UUIDs of
    /// `services` in the order to list them, without a TX power level.
    #[inline]
    #[must_use = "the content is only built"]
    pub const fn new(name: &'name [u8], appearance: u16, services: &'name [u16]) -> Self {
        Self { appearance, name, services, tx_power: None }
    }

    /// The same content with the TX power level `tx_power` in dBm, or
    /// without one.
    #[inline]
    #[must_use = "the content is only built"]
    pub const fn with_tx_power(self, tx_power: Option<i8>) -> Self { Self { tx_power, ..self } }
}

impl Data {
    /// Adds the appearance.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if it does not fit.
    #[inline]
    pub const fn appearance(&mut self, appearance: u16) -> Result<&mut Self, Overflow> {
        self.push(AD_APPEARANCE, &le16_bytes(appearance))
    }

    /// The structures written so far.
    #[inline]
    #[must_use = "the data is only read"]
    pub const fn as_bytes(&self) -> &[u8] { self.bytes.get(..usize::from(self.len)).unwrap_or_default() }

    /// Adds the flags.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if they do not fit.
    #[inline]
    pub const fn flags(&mut self, flags: u8) -> Result<&mut Self, Overflow> { self.push(AD_FLAGS, &[flags]) }

    /// Whether no structure was written.
    #[inline]
    #[must_use = "the length is only read"]
    pub const fn is_empty(&self) -> bool { self.len == 0 }

    /// The octets written so far.
    #[inline]
    #[must_use = "the length is only read"]
    pub const fn len(&self) -> usize { usize::from(self.len) }

    /// Adds the complete local name, UTF-8.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if it does not fit.
    #[inline]
    pub const fn name(&mut self, name: &[u8]) -> Result<&mut Self, Overflow> { self.push(AD_NAME, name) }

    /// Adds the complete local name if it fits, otherwise the shortened
    /// name: as much of it as fits, cut before a UTF-8 continuation octet.
    /// Returns whether the name was shortened.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if not even one character fits.
    #[inline]
    pub fn name_fitting(&mut self, name: &[u8]) -> Result<bool, Overflow> {
        if self.name(name).is_ok() {
            return Ok(false);
        }
        let mut room = self.room().saturating_sub(2).min(name.len());
        while name.get(room).is_some_and(|&octet| octet & 0xC0 == 0x80) {
            room = room.saturating_sub(1);
        }
        match name.get(..room) {
            Some(short) if !short.is_empty() => self.short_name(short).map(|_| true),
            _ => Err(Overflow::TooLong),
        }
    }

    /// No structures.
    #[inline]
    #[must_use = "the data is only built"]
    pub const fn new() -> Self { Self { bytes: [0; DATA_MAX], len: 0 } }

    /// Adds a structure of `kind` with `data`.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if it does not fit; the data is then unchanged.
    #[inline]
    pub const fn push(&mut self, kind: u8, data: &[u8]) -> Result<&mut Self, Overflow> {
        let start = self.len();
        let end = start.saturating_add(data.len()).saturating_add(2);
        let target = self.bytes.get_mut(start..end).ok_or(Overflow::TooLong)?;
        // Both fit an octet now: the structure fits the data's 31 octets.
        let length: u8 = data.len().saturating_add(1).saturating_cast();
        let (header, body) = target.split_at_mut(2);
        header.copy_from_slice(&[length, kind]);
        body.copy_from_slice(data);
        self.len = end.saturating_cast();
        Ok(self)
    }

    /// The octets left.
    const fn room(&self) -> usize { DATA_MAX.saturating_sub(self.len()) }

    /// Adds the complete list of 16-bit service UUIDs.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if it does not fit.
    #[inline]
    pub fn services(&mut self, uuids: &[u16]) -> Result<&mut Self, Overflow> {
        let mut list = [0; DATA_MAX];
        let octets = uuids.len().saturating_mul(2);
        let target = list.get_mut(..octets).ok_or(Overflow::TooLong)?;
        for (chunk, uuid) in target.as_chunks_mut::<2>().0.iter_mut().zip(uuids) {
            *chunk = le16_bytes(*uuid);
        }
        self.push(AD_SERVICES_16, target)
    }

    /// Adds the shortened local name, UTF-8.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if it does not fit.
    #[inline]
    pub const fn short_name(&mut self, name: &[u8]) -> Result<&mut Self, Overflow> { self.push(AD_SHORT_NAME, name) }

    /// Adds the TX power level in dBm.
    ///
    /// # Errors
    ///
    /// [`Overflow`] if it does not fit.
    #[inline]
    pub const fn tx_power(&mut self, dbm: i8) -> Result<&mut Self, Overflow> {
        self.push(AD_TX_POWER, &[dbm.cast_unsigned()])
    }
}

impl Default for Data {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl From<link::Error> for Error {
    #[inline]
    fn from(error: link::Error) -> Self { Self::Link(error) }
}

impl Control for Link<'_> {
    #[inline]
    fn call(&self, call: Call<'_>) -> Result<(), link::Error> {
        match call {
            Call::AcceptListAdd(peer) => self.accept_list_add(peer),
            Call::AcceptListClear => self.accept_list_clear(),
            Call::AddPeer { identity, local_irk, peer_irk } => self.add_peer(identity, peer_irk, local_irk),
            Call::Advertise { adv, params, scan } => self.advertise(&params, adv, scan),
            Call::ClearPeers => self.clear_peers(),
            Call::SetAddressResolution(enable) => self.set_address_resolution(enable),
            Call::SetIdentity(address) => self.set_identity(address),
            Call::SetPrivacyMode { device, identity } => self.set_privacy_mode(identity, device),
            Call::SetRpaTimeout(seconds) => self.set_rpa_timeout(seconds),
            Call::StopAdvertising => {
                self.stop_advertising();
                Ok(())
            },
        }
    }
}

impl Mode<'_> {
    /// Whether the mode advertises `phase` directed: a directed phase in
    /// [`Self::Reconnect`] for a bond without the central's identity
    /// resolving key, whose central therefore scans from its identity
    /// address, and only if that is an identity address, public or static
    /// random, which directed advertising can target. A central that sent its
    /// key scans from resolvable private addresses and would drop an
    /// advertisement directed to its identity. Elsewhere a directed phase
    /// advertises undirected at its interval, 20 ms.
    #[cfg(feature = "directed-advertising")]
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn directs(&self, phase: &Phase) -> bool {
        match *self {
            Self::Pairing => false,
            Self::Reconnect(bond) => phase.directed && bond.peer_irk.is_none() && is_identity(bond.peer),
        }
    }

    /// Whether the mode is discoverable and carries the name.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn discoverable(&self) -> bool { matches!(self, Self::Pairing) }

    /// Whether the security manager is to accept a Pairing Request.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn pairable(&self) -> bool { matches!(self, Self::Pairing) }

    /// The link layer's parameters for `phase`: connectable undirected on
    /// all three channels, from a resolvable private address, filtered on the
    /// filter accept list in [`Self::Reconnect`]; with the feature
    /// `directed-advertising`, for a phase the mode directs
    /// (`Self::directs`), high duty cycle directed advertising to the bonded
    /// central's identity, from the same private address.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn params(&self, phase: &Phase) -> AdvParams {
        let filter_policy = match *self {
            Self::Pairing => 0,
            Self::Reconnect(_) => FILTER_BONDED,
        };
        let undirected = AdvParams::new(Kind::ConnectableUndirected)
            .interval(phase.interval)
            .filter_policy(filter_policy)
            .private(true);
        #[cfg(feature = "directed-advertising")]
        if let Self::Reconnect(bond) = *self
            && self.directs(phase)
        {
            return AdvParams { kind: Kind::DirectedHighDuty, peer: bond.peer, ..undirected };
        }
        undirected
    }
}

impl Phase {
    /// A directed phase lasting `duration`, at most [`DIRECTED_MAX`]: high
    /// duty cycle directed advertising to the bonded central, for the start
    /// of a reconnection schedule (see the module documentation).
    #[cfg(feature = "directed-advertising")]
    #[inline]
    #[must_use = "the phase is only built"]
    pub const fn directed(duration: Duration) -> Self {
        let longest = Duration::from_ticks(duration.as_ticks().min(DIRECTED_MAX.as_ticks()));
        Self { directed: true, duration: longest, interval: DIRECTED_FALLBACK }
    }

    /// A phase with the interval `interval` in units of 0.625 ms, lasting
    /// `duration`.
    #[inline]
    #[must_use = "the phase is only built"]
    pub const fn new(interval: u16, duration: Duration) -> Self {
        Self {
            #[cfg(feature = "directed-advertising")]
            directed: false,
            duration,
            interval,
        }
    }
}

impl Schedule {
    /// The schedule of `phases` with the security deadline
    /// `security_deadline`.
    #[inline]
    #[must_use = "the schedule is only built"]
    pub const fn new(phases: &'static [Phase], security_deadline: Duration) -> Self {
        Self { phases, security_deadline }
    }

    /// The phase that runs `elapsed` after advertising started, or `None`
    /// once every phase has run.
    #[inline]
    #[must_use = "the phase is only looked up"]
    pub fn phase_at(&self, elapsed: Duration) -> Option<&'static Phase> {
        let mut end = Duration::from_ticks(0);
        self.phases.iter().find(|phase| {
            end = end.checked_add(phase.duration).unwrap_or(Duration::MAX);
            elapsed < end
        })
    }

    /// The time all phases take together, directed ones included.
    #[inline]
    #[must_use = "the time is only computed"]
    pub fn total(&self) -> Duration {
        self.phases
            .iter()
            .fold(Duration::from_ticks(0), |sum, phase| sum.checked_add(phase.duration).unwrap_or(Duration::MAX))
    }
}

/// Whether `peer` is an identity address, which directed advertising can
/// target: public, or static random.
#[cfg(feature = "directed-advertising")]
const fn is_identity(peer: Peer) -> bool {
    peer.address.last().is_some_and(const |&top| !peer.random || top & STATIC_RANDOM == STATIC_RANDOM)
}

#[cfg(test)] mod tests;
