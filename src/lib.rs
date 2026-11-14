//! Bluetooth LE link layer for the nRF52832 and the nRF51, and a minimal host
//! for Linux and `BlueZ`, which talks to the link layer through the typed API
//! of [`link`] instead of HCI.

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
// lose bits; and `#[rustc_unroll(never)]` (`loop_hints`) on two loops of
// the host, off the link layer, which keeps them rolled: the byte order turn
// of pairing's public keys and the copy of an ATT read value. (The 3.2 KB
// once measured on the nRF52832 counted two more loops, of the P-256 code of
// our own the `p256` crate has replaced; the two left are not measured on
// their own.)
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
    loop_hints
)]
// Rustdoc marks each item behind a Cargo feature with the feature it needs.
#![cfg_attr(doc, feature(doc_cfg))]

#[cfg(all(feature = "nrf52832", feature = "nrf51"))]
compile_error!(
    "the chip features nrf52832 and nrf51 exclude each other: build for the nRF51 with default-features = false"
);
#[cfg(not(any(feature = "nrf52832", feature = "nrf51")))]
compile_error!("enable a chip feature: nrf52832, the default, or nrf51");
#[cfg(all(feature = "nrf51", feature = "data-length"))]
compile_error!("the nRF51 CCM encrypts payloads of up to 27 octets: the data-length feature needs the nRF52832");

/// Logging, first: its macro serves the modules after it.
#[macro_use]
mod log;
/// Connectable advertising.
pub mod advertiser;
/// Integers to and from octets in a given byte order.
mod bytes;
/// Data channel map and channel selection.
pub mod channel;
/// Register code that differs between the chips.
#[cfg(feature = "nrf51")]
#[path = "chip/nrf51.rs"]
mod chip;
/// Register code that differs between the chips.
#[cfg(feature = "nrf52832")]
#[path = "chip/nrf52832.rs"]
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
