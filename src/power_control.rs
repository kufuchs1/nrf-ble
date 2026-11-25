//! Transmit power that follows the link: lower while the central is heard
//! strongly, higher when its packets get weak or go missing.
//!
//! The path is taken as symmetric and the central as sending at 0 dBm, so the
//! central hears this peripheral at about its own power plus the received
//! signal strength. Power steps down while that estimate stays above
//! `TARGET_HIGH_DBM` and up below `TARGET_LOW_DBM`. A central that sends
//! stronger than assumed still hears the device 15 dB above its
//! sensitivity. A packet of ours that the central did not acknowledge raises
//! the power at once, and keeps it from stepping down for
//! `HOLD_AFTER_LOSS` packets. Packets of the central that were not
//! received say nothing about this side's power and are ignored.
//!
//! A central that runs power control measures this side's signal itself and
//! asks for a change. Its request becomes a floor for `FLOOR_HOLD`
//! received packets: the own control does not step below it in that time.
//! Afterwards the own control decides again, and each change it makes is
//! reported to a central that asked for reports. Some centrals ask for the
//! maximum once and never again, which a permanent floor would keep for the
//! whole connection. A later request of the central sets a new floor.
//!
//! The power never rises above a ceiling: [`CEILING_DBM`], +4 dBm, unless
//! the firmware chooses another with
//! [`Link::set_max_tx_power`](crate::link::Link::set_max_tx_power). The
//! power steps down only to a level at which the central would still hear
//! this side at `TARGET_LOW_DBM` or above, so the 20 dB between the
//! nRF52833's -40 and -20 dBm do not make it step back and forth.

use crate::chip;

/// Transmit power levels in dBm, lowest first, as the chip's radio offers
/// them: -20 to +4 dBm, with +3 dBm on the nRF52832, and -40 dBm and -20 to
/// +8 dBm on the nRF52833.
pub const LEVELS_DBM: [i8; chip::LEVELS_DBM.len()] = chip::LEVELS_DBM;
/// Level at the start of a connection and for advertising: 0 dBm.
pub const DEFAULT_LEVEL: usize = level_at_most(0);
/// Highest transmit power in dBm a connection uses unless the firmware
/// chooses another ceiling: +4 dBm, the highest level of the nRF52832 and
/// the nRF51.
///
/// The nRF52833 goes up to +8 dBm. Above +4 dBm the radio needs supply
/// headroom that a board may not have, and the product's regulatory
/// approval has to cover the higher power, so a firmware chooses its
/// ceiling itself with
/// [`Link::set_max_tx_power`](crate::link::Link::set_max_tx_power).
pub const CEILING_DBM: i8 = 4;

// Every level is a setting of the radio's TXPOWER register, the levels
// ascend, the default is 0 dBm and the default ceiling +4 dBm.
const _: () = {
    let mut rest = LEVELS_DBM.as_slice();
    while let Some((&level, tail)) = rest.split_first() {
        assert!(chip::txpower(level).to_bits().cast_signed() == level, "a level is not a radio setting");
        assert!(tail.first().is_none_or(const |&next| next > level), "the levels do not ascend");
        rest = tail;
    }
    assert!(matches!(LEVELS_DBM.get(DEFAULT_LEVEL), Some(&0)), "the default level is not 0 dBm");
    assert!(matches!(LEVELS_DBM.get(ceiling_level(CEILING_DBM)), Some(&4)), "the default ceiling is not +4 dBm");
};
/// Estimated signal at the central above which the power steps down.
///
/// TODO(nRF51): the nRF51's RSSI is coarser than the nRF52832's, about
/// ±6 dB against ±2 dB as the nRF51822 specifies it; check the nRF51802
/// product specification, and measure on hardware whether the 12 dB between
/// the targets keeps the power from stepping back and forth.
const TARGET_HIGH_DBM: i32 = -60;
/// Estimated signal at the central below which the power steps up.
const TARGET_LOW_DBM: i32 = -72;
/// Received packets after a loss before the power may step down again.
const HOLD_AFTER_LOSS: u8 = 64;
/// Received packets for which a level the central asked for is a floor.
const FLOOR_HOLD: u16 = 1024;
/// Received packets between two decisions.
const SAMPLES_PER_DECISION: u8 = 16;
/// Fixed point factor of the average.
const SCALE: i32 = 16;
/// Weight of a new sample in the average, as a shift.
const SMOOTHING_SHIFT: u32 = 3;

/// Transmit power control of one connection.
#[derive(Clone, Copy)]
pub struct PowerControl {
    /// Average received signal strength in dBm times [`SCALE`].
    average:    Option<i32>,
    /// Index into [`LEVELS_DBM`] the own control does not step below: the
    /// level the central last asked for, while it holds.
    floor:      usize,
    /// Received packets until the floor ends.
    floor_left: u16,
    /// Received packets until the power may step down again.
    hold:       u8,
    /// Index into [`LEVELS_DBM`].
    level:      usize,
    /// Samples since the last decision.
    samples:    u8,
    /// Index into [`LEVELS_DBM`] of the ceiling, which the power never
    /// exceeds.
    top:        usize,
}

impl PowerControl {
    /// Received signal strength in dBm, averaged, once a packet arrived.
    #[inline]
    #[must_use = "the signal strength is only read"]
    pub const fn average_dbm(&self) -> Option<i32> { self.average.map(const |average| average.strict_div(SCALE)) }

    /// Steps the power down or up by one level from the average: down only
    /// if the central would still hear the lower level at `TARGET_LOW_DBM`
    /// or above, up only to the ceiling.
    const fn decide(&mut self) {
        let Some(average) = self.average else { return };
        let heard = average.strict_div(SCALE);
        let lower = self.level.saturating_sub(1);
        if at_central(self.level, heard) > TARGET_HIGH_DBM
            && self.hold == 0
            && self.level > self.floor
            && at_central(lower, heard) >= TARGET_LOW_DBM
        {
            self.level = lower;
        } else if at_central(self.level, heard) < TARGET_LOW_DBM {
            self.level = self.level.saturating_add(1).min(self.top);
        } else {
            // Within the window, or a step down would leave it: keep the
            // level.
        }
    }

    /// Index into [`LEVELS_DBM`] to send with.
    #[inline]
    #[must_use = "the level is only read"]
    pub const fn level(&self) -> usize { self.level }

    /// Moves to the level closest to `dbm` up to the ceiling, as the central
    /// asked, and keeps the own control from stepping below it for
    /// `FLOOR_HOLD` packets.
    #[inline]
    pub fn move_to(&mut self, dbm: i32) {
        let allowed = LEVELS_DBM.get(..=self.top).unwrap_or(&LEVELS_DBM);
        let closest = allowed.iter().enumerate().min_by_key(|&(_, &level)| i32::from(level).abs_diff(dbm));
        self.level = closest.map_or(self.level, |(index, _)| index);
        self.floor = self.level;
        self.floor_left = FLOOR_HOLD;
        self.samples = 0;
        self.hold = HOLD_AFTER_LOSS;
    }

    /// Starts at [`DEFAULT_LEVEL`], with the ceiling at [`CEILING_DBM`].
    #[inline]
    #[must_use = "the control is only created"]
    pub const fn new() -> Self {
        Self {
            average:    None,
            floor:      0,
            floor_left: 0,
            hold:       0,
            level:      DEFAULT_LEVEL,
            samples:    0,
            top:        ceiling_level(CEILING_DBM),
        }
    }

    /// Takes a packet of ours that the central did not acknowledge.
    #[inline]
    pub const fn on_loss(&mut self) {
        self.level = self.level.saturating_add(1).min(self.top);
        self.samples = 0;
        self.hold = HOLD_AFTER_LOSS;
    }

    /// Takes the signal strength of a packet received with a valid CRC, in
    /// -dBm as the radio reports it.
    #[inline]
    pub const fn on_packet(&mut self, rssi: u8) {
        let sample = i32::from(rssi).saturating_mul(SCALE.strict_neg());
        self.average = Some(self.average.map_or(sample, const |average| {
            average.saturating_add(sample.saturating_sub(average).wrapping_shr(SMOOTHING_SHIFT))
        }));
        self.samples = self.samples.saturating_add(1);
        self.hold = self.hold.saturating_sub(1);
        if self.floor_left != 0 {
            self.floor_left = self.floor_left.saturating_sub(1);
            if self.floor_left == 0 {
                self.floor = 0;
            }
        }
        if self.samples >= SAMPLES_PER_DECISION {
            self.samples = 0;
            self.decide();
        }
    }

    /// Sets the ceiling to `dbm`: the highest level not above it, and at
    /// least [`DEFAULT_LEVEL`] ([`ceiling_level`]). A level or floor above
    /// the ceiling comes down to it.
    #[inline]
    pub const fn set_ceiling(&mut self, dbm: i8) {
        self.top = ceiling_level(dbm);
        self.level = self.level.min(self.top);
        self.floor = self.floor.min(self.top);
    }

    /// Index into [`LEVELS_DBM`] of the ceiling.
    #[inline]
    #[must_use = "the level is only read"]
    pub const fn top(&self) -> usize { self.top }
}

impl Default for PowerControl {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// The estimated signal at the central while this side sends at `level`
/// and hears the central at `heard` dBm, the path taken as symmetric and the
/// central as sending at 0 dBm.
const fn at_central(level: usize, heard: i32) -> i32 {
    i32::from(LEVELS_DBM.get(level).copied().unwrap_or_default()).saturating_add(heard)
}

/// Index into [`LEVELS_DBM`] of the ceiling `dbm`: the highest level not
/// above it, and at least [`DEFAULT_LEVEL`], so that the ceiling never lies
/// below the power a link starts with.
#[inline]
#[must_use = "the level is only computed"]
pub const fn ceiling_level(dbm: i8) -> usize { level_at_most(dbm).max(DEFAULT_LEVEL) }

/// Index into [`LEVELS_DBM`] of the highest level not above `dbm`, or of
/// the lowest level if all are above it.
const fn level_at_most(dbm: i8) -> usize {
    let mut found: usize = 0;
    let mut index: usize = 0;
    let mut rest = LEVELS_DBM.as_slice();
    while let Some((&level, tail)) = rest.split_first() {
        if level <= dbm {
            found = index;
        }
        index = index.saturating_add(1);
        rest = tail;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A central so close that the power goes down to the lowest level on
    /// every chip: 20 dB above the window at the second level, and within
    /// it at the lowest.
    fn close() -> u8 { u8::try_from(i32::from(LEVELS_DBM[0]) + 60).unwrap() }

    fn settle(control: &mut PowerControl, rssi: u8) {
        for _ in 0..u32::from(SAMPLES_PER_DECISION) * 20 {
            control.on_packet(rssi);
        }
    }

    /// Index of the default ceiling, +4 dBm.
    fn top() -> usize { PowerControl::new().top() }

    #[test]
    fn the_nrf51_alone_lacks_3_dbm() {
        // The rest of the table is checked at compile time, beside it.
        assert_eq!(LEVELS_DBM.contains(&3), !cfg!(feature = "nrf51"));
    }

    #[test]
    fn only_the_nrf52833_goes_from_minus_40_to_plus_8_dbm() {
        let range = (LEVELS_DBM[0], LEVELS_DBM[LEVELS_DBM.len() - 1]);
        assert_eq!(range, if cfg!(feature = "nrf52833") { (-40, 8) } else { (-20, 4) });
    }

    #[test]
    fn the_default_ceiling_is_4_dbm_on_every_chip() {
        assert_eq!(LEVELS_DBM[top()], 4);
        assert_eq!(LEVELS_DBM[DEFAULT_LEVEL], 0);
    }

    #[test]
    fn a_ceiling_rounds_down_to_a_level_and_never_below_0_dbm() {
        assert_eq!(ceiling_level(i8::MAX), LEVELS_DBM.len() - 1);
        assert_eq!(ceiling_level(4), top());
        assert_eq!(ceiling_level(-10), DEFAULT_LEVEL);
        assert_eq!(ceiling_level(i8::MIN), DEFAULT_LEVEL);
        assert_eq!(LEVELS_DBM[ceiling_level(1)], 0);
        assert_eq!(LEVELS_DBM[ceiling_level(3)], if cfg!(feature = "nrf51") { 0 } else { 3 });
        assert_eq!(LEVELS_DBM[ceiling_level(7)], if cfg!(feature = "nrf52833") { 7 } else { 4 });
    }

    #[test]
    fn a_central_close_by_brings_the_power_to_the_minimum() {
        let mut control = PowerControl::new();
        settle(&mut control, close());
        assert_eq!(control.level(), 0);
    }

    #[test]
    fn a_weak_central_brings_the_power_to_the_ceiling() {
        let mut control = PowerControl::new();
        settle(&mut control, 85);
        assert_eq!(control.level(), top());
        assert_eq!(LEVELS_DBM[control.level()], 4);
    }

    #[test]
    fn a_raised_ceiling_lets_the_power_reach_the_highest_level() {
        let mut control = PowerControl::new();
        control.set_ceiling(i8::MAX);
        settle(&mut control, 95);
        assert_eq!(control.level(), LEVELS_DBM.len() - 1);
        assert_eq!(LEVELS_DBM[control.level()], if cfg!(feature = "nrf52833") { 8 } else { 4 });
    }

    #[test]
    fn a_lowered_ceiling_brings_the_level_and_the_floor_down() {
        let mut control = PowerControl::new();
        control.move_to(4);
        control.set_ceiling(0);
        assert_eq!((control.level(), control.top()), (DEFAULT_LEVEL, DEFAULT_LEVEL));
        control.on_loss();
        settle(&mut control, 85);
        assert_eq!(control.level(), DEFAULT_LEVEL);
        // The central's request still holds as a floor, at the ceiling.
        settle(&mut control, close());
        assert_eq!(control.level(), DEFAULT_LEVEL);
    }

    #[test]
    fn the_power_settles_where_the_central_hears_it_in_the_window() {
        for rssi in 45..80 {
            let mut control = PowerControl::new();
            settle(&mut control, rssi);
            let at_central = i32::from(LEVELS_DBM[control.level()]) - i32::from(rssi);
            let at_limit = control.level() == 0 || control.level() == top();
            assert!(at_limit || (TARGET_LOW_DBM..=TARGET_HIGH_DBM).contains(&at_central), "rssi -{rssi}");
        }
    }

    #[test]
    fn the_power_settles_without_stepping_back_and_forth() {
        for rssi in 0..=110 {
            let mut control = PowerControl::new();
            control.set_ceiling(i8::MAX);
            settle(&mut control, rssi);
            let settled = control.level();
            for _ in 0..u32::from(SAMPLES_PER_DECISION) * 8 {
                control.on_packet(rssi);
                assert_eq!(control.level(), settled, "rssi -{rssi}");
            }
            // Above the window only where a step down would leave it below.
            let at_central = |level: usize| i32::from(LEVELS_DBM[level]) - i32::from(rssi);
            if settled != 0 && at_central(settled) > TARGET_HIGH_DBM {
                assert!(at_central(settled - 1) < TARGET_LOW_DBM, "rssi -{rssi}");
            }
        }
    }

    #[test]
    fn a_lost_packet_raises_the_power_at_once() {
        let mut control = PowerControl::new();
        settle(&mut control, close());
        control.on_loss();
        assert_eq!(control.level(), 1);
        for _ in 0..20 {
            control.on_loss();
        }
        assert_eq!(control.level(), top());
    }

    #[test]
    fn after_a_loss_the_power_holds_before_stepping_down() {
        let mut control = PowerControl::new();
        settle(&mut control, close());
        control.on_loss();
        for _ in 0..HOLD_AFTER_LOSS - 1 {
            control.on_packet(close());
        }
        assert_eq!(control.level(), 1);
        settle(&mut control, close());
        assert_eq!(control.level(), 0);
    }

    #[test]
    fn a_requested_power_moves_to_the_closest_level_and_holds() {
        let mut control = PowerControl::new();
        control.move_to(-13);
        assert_eq!(LEVELS_DBM[control.level()], -12);
        control.move_to(40);
        assert_eq!(control.level(), top());
        control.move_to(-12);
        for _ in 0..SAMPLES_PER_DECISION {
            control.on_packet(close());
        }
        assert_eq!(LEVELS_DBM[control.level()], -12);
    }

    #[test]
    fn a_requested_power_is_the_floor_until_the_central_lowers_it() {
        let mut control = PowerControl::new();
        control.move_to(-4);
        settle(&mut control, close());
        assert_eq!(LEVELS_DBM[control.level()], -4);
        settle(&mut control, 85);
        assert_eq!(control.level(), top());
        settle(&mut control, close());
        assert_eq!(LEVELS_DBM[control.level()], -4);
        control.move_to(-12);
        settle(&mut control, close());
        assert_eq!(LEVELS_DBM[control.level()], -12);
    }

    #[test]
    fn one_decision_moves_one_level() {
        let mut control = PowerControl::new();
        for _ in 0..SAMPLES_PER_DECISION {
            control.on_packet(close());
        }
        assert_eq!(control.level(), DEFAULT_LEVEL - 1);
    }

    #[test]
    fn a_level_the_central_asked_for_holds_only_for_a_while() {
        let mut control = PowerControl::new();
        control.move_to(4);
        for _ in 0..FLOOR_HOLD - 1 {
            control.on_packet(close());
        }
        assert_eq!(control.level(), top());
        settle(&mut control, close());
        assert_eq!(control.level(), 0);
    }
}
