//! Bluetooth LE link layer for the nRF52832, the nRF52833 and the nRF51, and
//! a minimal host for Linux and `BlueZ`, which talks to the link layer
//! through the typed API of [`link`] instead of HCI.

#![no_std]
// Const trait implementations of the standard library, so that const
// functions use the methods of Option, Result, Ord, From and TryFrom, `?`,
// slice ranges, `RangeInclusive::contains` for the range checks
// (`const_range`) and `for` loops over ranges (`const_iter`) like the rest
// of the code, instead of matches, casts and while loops.
// Beside them: default values on struct fields (`default_field_values`), so
// a starting value stands at its field and the constructor writes `..`;
// `saturating_cast` and `truncate` (`integer_casts`,
// `integer_widen_truncate`) for the conversions that saturate or cannot
// lose bits; `split_array_ref` (`split_array`) for the front of a fixed
// array, such as the X coordinate of a public key, with no `Option` that
// cannot be `None`; and `#[rustc_unroll(never)]` (`loop_hints`) on one loop of
// the host, off the link layer, which keeps it rolled: the byte order turn
// of pairing's public keys.
#![feature(
    const_bool,
    const_closures,
    const_cmp,
    const_convert,
    const_index,
    const_iter,
    const_option_ops,
    const_range,
    const_result_trait_fn,
    const_trait_impl,
    const_try,
    default_field_values,
    derive_const,
    integer_casts,
    integer_widen_truncate,
    loop_hints,
    split_array
)]
// Rustdoc marks each item behind a Cargo feature with the feature it needs,
// but for the internal `_nrf52`, which the chip features nrf52832 and
// nrf52833 set: an item behind it alone carries no mark.
#![cfg_attr(doc, feature(doc_cfg))]
#![cfg_attr(doc, doc(auto_cfg(hide(feature, values("_nrf52")))))]
// The fuzz test of the credit based channels checks that it runs with overflow
// checks (`cfg!(overflow_checks)`).
#![cfg_attr(all(test, feature = "eatt"), feature(cfg_overflow_checks))]

#[cfg(all(feature = "nrf52832", feature = "nrf52833"))]
compile_error!(
    "the chip features nrf52832 and nrf52833 exclude each other: build for the nRF52833 with default-features = false"
);
#[cfg(all(feature = "nrf52832", feature = "nrf51"))]
compile_error!(
    "the chip features nrf52832 and nrf51 exclude each other: build for the nRF51 with default-features = false"
);
#[cfg(all(feature = "nrf52833", feature = "nrf51"))]
compile_error!("the chip features nrf52833 and nrf51 exclude each other: enable one chip feature only");
#[cfg(not(any(feature = "nrf52832", feature = "nrf52833", feature = "nrf51")))]
compile_error!("enable a chip feature: nrf52832, the default, nrf52833 or nrf51");
#[cfg(all(feature = "_nrf52", not(any(feature = "nrf52832", feature = "nrf52833"))))]
compile_error!("_nrf52 is internal: enable the chip feature nrf52832 or nrf52833 instead");
#[cfg(all(feature = "nrf51", feature = "data-length"))]
compile_error!(
    "the nRF51 CCM encrypts payloads of up to 27 octets: the data-length feature needs the nRF52832 or the nRF52833"
);

/// Logging, first: its macros serve the modules after it.
#[macro_use]
mod log;
/// Connectable advertising.
pub mod advertiser;
/// Data channel map and channel selection.
pub mod channel;
/// Register code that differs between the chips.
#[cfg(feature = "nrf51")]
#[path = "chip/nrf51.rs"]
mod chip;
/// Register code that differs between the chips.
#[cfg(feature = "_nrf52")]
#[path = "chip/nrf52.rs"]
mod chip;
/// Microsecond time base.
pub mod clock;
/// Peripheral connections.
pub mod connection;
/// The link layer task.
pub mod controller;
/// Link encryption, and AES-128 on the ECB.
pub mod crypto;
/// Radio executor progress monitoring.
pub mod health;
/// The minimal host: L2CAP, ATT and GATT, the security manager, advertising,
/// the protocol engine and its async glue.
pub mod host;
/// The typed interface between the link layer and the host.
pub mod link;
/// Flash maintenance while disconnected.
pub mod maintenance;
/// Link layer packet formats.
pub mod pdu;
/// Transmit power control.
pub mod power_control;
/// BLE radio driver.
pub mod radio;
/// Shared synchronous and async hardware entropy.
pub mod rng;
/// Sleeping on peripheral events.
mod sleep;

/// The PPI channels of the link layer on the nRF52 chips: those of the clock,
/// the turnaround and the CCM.
#[cfg(feature = "_nrf52")]
const LINK_PPI_CHANNELS: [usize; 10] = [
    clock::PPI_RESUME,
    clock::PPI_SYNC,
    clock::PPI_CALIBRATE,
    radio::PPI_SWITCH_START,
    radio::PPI_SWITCH_ENABLE,
    clock::PPI_TXEN,
    clock::PPI_RXEN,
    crypto::PPI_CRYPT,
    clock::PPI_ADDRESS,
    clock::PPI_END,
];
/// The PPI channels of the link layer on the nRF51: those of the clock, the
/// channels standing in for the FORK of its self-disabling channels, and
/// the CCM's. The radio times its turnarounds itself.
#[cfg(feature = "nrf51")]
const LINK_PPI_CHANNELS: [usize; 10] = [
    clock::PPI_RESUME,
    clock::PPI_SYNC,
    clock::PPI_CALIBRATE,
    chip::fork_channel(clock::PPI_SYNC),
    chip::fork_channel(clock::PPI_CALIBRATE),
    clock::PPI_TXEN,
    clock::PPI_RXEN,
    crypto::PPI_CRYPT,
    clock::PPI_ADDRESS,
    clock::PPI_END,
];
/// The PPI channel groups of the link layer: those of its self-disabling
/// channels.
const LINK_PPI_GROUPS: [usize; 2] = [clock::PPI_GROUP_CALIBRATE, clock::PPI_GROUP_SYNC];
/// Every PPI channel the link layer uses on the selected chip, as a mask
/// with bit `n` set for channel `n`.
///
/// They are programmable channels and fixed channels between TIMER0, RTC0,
/// the clock, the radio and the CCM, and on the nRF52 chips the two
/// programmable channels of the turnaround timer. On the nRF51 they include
/// the programmable channels that stand in for the FORK registers it lacks.
///
/// The link layer programs these channels and enables and disables them,
/// some of them within the interframe space. A firmware must not program,
/// enable, disable or group them. It switches its own channels through
/// `CHENSET` and `CHENCLR` only, as writing `CHEN` would switch these too.
/// A firmware that uses PPI checks its channels against this mask at
/// compile time, for example with
/// `const _: () = assert!(nrf_ble::PPI_CHANNELS & MY_CHANNELS == 0);`.
///
/// The link layer owns the Embassy tokens of the channels that have one
/// ([`clock::Ppi`], [`clock::CalibrationPpi`] and on the nRF52 chips
/// `radio::Ppi`), so no Embassy driver can take them. The fixed channels of
/// the nRF51 have no tokens, and only this mask covers them.
pub const PPI_CHANNELS: u32 = ppi_mask(&LINK_PPI_CHANNELS);
/// Every PPI channel group the link layer uses, as a mask with bit `n` set
/// for group `n`.
///
/// The link layer writes the channels of these groups and triggers their
/// enable and disable tasks, and owns their Embassy tokens. A firmware must
/// not use them, and checks its own groups against this mask at compile
/// time like [`PPI_CHANNELS`].
pub const PPI_GROUPS: u8 = ppi_mask(&LINK_PPI_GROUPS).strict_cast();

// Each list names every channel or group once: two constants on the same
// number would leave the mask a bit short of the list.
const _: () = assert!(
    PPI_CHANNELS.count_ones() == LINK_PPI_CHANNELS.len().strict_cast(),
    "two PPI channels of the link layer have the same number"
);
const _: () = assert!(
    PPI_GROUPS.count_ones() == LINK_PPI_GROUPS.len().strict_cast(),
    "two PPI channel groups of the link layer have the same number"
);

/// The mask with bit `n` set for each channel or group `n` in `numbers`.
const fn ppi_mask(numbers: &[usize]) -> u32 {
    let mut mask = 0;
    let mut rest = numbers;
    while let Some((&number, tail)) = rest.split_first() {
        mask |= 1_u32.strict_shl(number.strict_cast());
        rest = tail;
    }
    mask
}

#[cfg(test)]
mod tests {
    use crate::clock::{CalibrationPpi, Ppi};
    use embassy_nrf::peripherals;

    /// The token of `$peripheral`, which a test only builds.
    macro_rules! token {
        ($peripheral:ident) => {
            // SAFETY: the test builds the token alone, and nothing else
            // holds it.
            unsafe { peripherals::$peripheral::steal() }
        };
    }

    /// The token sets check in debug builds that each token is the channel
    /// or group its constant numbers.
    #[test]
    fn ppi_tokens_are_the_channels_programmed() {
        #[cfg(feature = "_nrf52")]
        let _clock = Ppi::new(
            token!(PPI_CH0),
            token!(PPI_CH1),
            token!(PPI_CH20),
            token!(PPI_CH21),
            token!(PPI_CH26),
            token!(PPI_CH27),
            token!(PPI_GROUP1),
        );
        #[cfg(feature = "nrf51")]
        let _clock = Ppi::new(token!(PPI_CH0), token!(PPI_CH1), token!(PPI_CH9), token!(PPI_GROUP1));
        let _calibration = CalibrationPpi::new(
            token!(PPI_CH3),
            #[cfg(feature = "nrf51")]
            token!(PPI_CH11),
            token!(PPI_GROUP0),
        );
        #[cfg(feature = "_nrf52")]
        let _radio = crate::radio::Ppi::new(token!(PPI_CH4), token!(PPI_CH5), token!(PPI_CH25));
    }
}
