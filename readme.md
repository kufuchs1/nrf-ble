# nrf-ble

A Bluetooth LE link layer for the nRF52832 and the nRF51, written in Rust on Embassy, together with a minimal host for
Linux and BlueZ in the same crate. The link layer drives the radio directly; the host serves one central as a
peripheral. The nRF51 support, for an nRF51802, builds and passes the host tests but has not run on hardware yet: see
[nRF51](#nrf51).

## Status

nrf-ble starts as a copy of nrf-ll, the link layer of the replacement firmwares for the Logitech MX Keys S keyboard
and the MX Master 3S mouse, which talks to a host stack such as [TrouBLE](https://github.com/embassy-rs/trouble) over
HCI. nrf-ll stays as it is, and the MX firmwares keep using it until they move here.

This crate has no HCI: no bt-hci, no TrouBLE, and no command or event encoded into bytes. The host (`src/host`) talks
to the link layer through the typed Rust API of [`src/link.rs`](src/link.rs). Its only target is Linux with BlueZ,
and its first user is the firmware of the Logitech Spotlight remote (an nRF51802), later the MX firmwares. The design is
in [`docs/host/design.md`](../docs/host/design.md), with the fixes of its reviews; it was written for a separate host
crate and an HCI adapter, and this crate replaces both with one crate and the typed API.

What is done so far:

- The link layer as copied from nrf-ll, with nrf-ll's byte level HCI module replaced by the typed API, and with the
  peripheral latency hold (see below). Every behaviour nrf-ll's HCI offered stays, as a typed call: identity, filter
  accept list, resolving list and privacy, advertising, long term key replies, disconnection, connection parameter
  requests and replies, data length, PHY, authenticated payload timeout, RSSI and the central's features and version.
- The host's AES seam (`host::Aes`, the hardware ECB behind `host::Ecb`, software AES in the tests).
- The cryptography of pairing: AES-CMAC and f4, f5, f6, g2 and ah in `host::smp::toolbox`, and P-256 key generation,
  Diffie-Hellman and public key checks in `host::smp::ecc`, with a constant time scalar multiplication of our own.
- The security manager (`host::smp::Responder`): LE Secure Connections Just Works pairing as responder, with bonding and
  the identity keys both ways, as a state machine without input or output of its own. The P-256 multiplications are
  jobs it hands out for a task of their own; the 30 s timer is a deadline the engine drives. It is tested against a
  reference central built from the toolbox, octet for octet, with every refusal, failure and the timeout.
- L2CAP (`host::l2cap`: the fixed channels, reassembly into one 72 octet buffer, fragmenting on demand), LE signalling
  (`host::signal`: the connection parameter update request and command rejects), the ATT server at MTU 23
  (`host::att`) and the GATT table (`host::gatt`: the `gatt!` macro, per-link CCCD state, a constant table hash and the
  Spotlight table in `host::gatt::spotlight`).
- Our identity (`host::identity`: the address and identity resolving key derived from the device secret the way the MX
  firmwares do), advertising (`host::adv`: the advertising data writer, the pairing and reconnect modes with their
  phases, and their setup of the link layer's accept list, resolving list and privacy) and the bond (`host::bond`: the
  record of the one central with its fixed 50 octet stored form).
- The engine (`host::engine::Engine`): all of the host's protocol state for one link, without futures. It takes the
  link layer's events and fragments, the time and the results of the P-256 jobs, and gives the fragments to send (pulled
  one at a time, the connection parameter request leaving one place of the link layer's queue free), the calls of the
  link layer, its next deadline, the jobs and the events for the application. It holds the peripheral latency off until
  discovery is over (the link encrypted and ATT idle for 500 ms), asks for the table's preferred connection parameters
  with the L2CAP request once ATT has been idle for 1.5 s, answers a key request for EDIV 0 and Rand 0 only, with the
  pairing's key or the bond's for the bonded central, restores the bond's client characteristic configuration only once
  the link is encrypted with the bond's key, builds the bond from the pairing and keeps its subscriptions up to date,
  and ends a link that is not encrypted in time, whose pairing failed or timed out.
- The async glue (`host::Host`, `host::Conn`): a static `Host` whose engine sits behind a thread mode mutex, never a
  critical section. `Host::run` waits for the link layer, the next deadline, room in the link layer's queue while output
  waits, or a wake-up; `Host::crypto` runs the P-256 jobs with the firmware's watchdog hook before each multiplication
  and a yield between jobs; `Host::advertise` waits for the key pair before pairable advertising, runs the schedule's
  phases and keeps or ends a link that arrives after its future was dropped; `Conn::notify` paces by acknowledgement,
  with at most two fragments in flight and one place of the queue kept free. The link layer is reached through the
  `host::Port` trait, which `link::Link` implements; the host tests drive the whole host over a stand-in link layer.
  The module documentation of `host` shows how the Spotlight firmware wires it.

On the nRF51 (thumbv6m, measured with `-Zprint-type-sizes`) the static `Host<Link>` takes 896 bytes, 800 of them the
engine (368 the security manager), the `Host::run` future 136 bytes, the `Host::crypto` future 32, a `Host::advertise`
future 96 and a `Conn::notify` future 48.

Nothing has run on hardware or against BlueZ yet.

## The typed link API

`link::Shared` is the static the link layer task and the host share; `link::Link` is the host's copyable handle on it.

- **Epochs:** each link has an `Epoch`, which `Event::Connected` and `Link::info` carry. A call for a link that ended
  returns `Error::Gone` and has no effect on the next link.
- **Events:** `Link::next` returns `Rx::Event` and `Rx::Acl`. The event queue holds 6 events of 12 bytes, as the
  thread executor stalls for about 3 s during a P-256 multiplication; the connection keeps 3 more until there is room.
  `Event::Connected` comes before the first received fragment of its link and `Event::Disconnected` after its last;
  events and fragments are not otherwise in one order.
- **Received data:** each `AclIn` carries an `encrypted` flag, set when the link layer received the PDU, so a security
  check does not depend on when the host learns of the encryption.
- **Sending:** `try_send` and `send` queue one fragment of up to 27 octets (251 with `data-length`), `tx_room` gives
  the free room, `tx_room_changed` waits until the link layer took a fragment or the central acknowledged some, and
  `in_flight` counts the fragments the central has not acknowledged, so the host can keep at most two fragments in
  flight and learn when the central received what it sent.
- **Link information:** `Link::info` gives the central's address on the air with its type, its resolved identity
  separately, our own address on the air (the resolvable private address or the identity), the parameters and the
  central's clock accuracy: pairing uses the addresses on the air.
- **Long term key:** `ltk_reply` takes the key least significant octet first, as the link layer uses it.

## What it does

- **Advertising:** legacy advertising on the LE 1M PHY: all five advertising types, scan responses, the advertising
  channel map and the filter accept list. Resolvable private addresses from the identity resolving key the host puts
  into the resolving list, renewed when they expire after 15 minutes, or the timeout the host sets, also while
  advertising keeps running; peer addresses in the resolving list are resolved for the filter accept list and for
  directed advertising. A reset forgets every key the host gave.
- **Connections:** as peripheral, with channel selection algorithm 1 or 2, as the central chooses. It answers the LL
  control procedures a central starts. A host that called `Link::set_host_decides_params` decides on the parameters a central
  asks for (`Event::ParamsRequested`, `Link::reply_params`), and has them rejected if it does not answer in 30 s;
  otherwise the link layer accepts any valid parameters. Our own procedures wait until the central's update arrives. A
  `Link::request_params` the host makes while it answers is part of that answer: it leaves an own request of the host
  alone and completes when the central's procedure ends, with the update or with the reason it ended. Every packet
  from the central gets an answer, also one with a CRC error, and sets the anchor; a control PDU of the wrong length
  is answered as unknown.
- **Link end:** the host reads every packet the link acknowledged before it gets `Event::Disconnected`; requests of
  the host for a link that ended cannot reach the next one, and every link starts with the default authenticated
  payload timeout.
- **RSSI:** `Link::rssi` gives the averaged signal strength of the central's packets. Keys the host gave, and the keys
  of a link, are overwritten once they are no longer needed.
- **Encryption:** AES-CCM. A central can refresh the key of an encrypted link: encryption pauses and starts again with
  the new key without a disconnection. An encrypted link has to carry a packet with a valid MIC at least every 30 s,
  or as long as the host sets: after three quarters of that time without one, the link layer pings the central, and
  the host learns when the whole time passes. A central that leaves the ping unanswered for 40 s ends the link with
  an LL response timeout, as any other procedure does. A key reply for a link that ended before the host answered
  returns `Error::Gone` and has no effect on the next link.
- **Connection parameter requests from the host** run one at a time: `Link::request_params` returns
  `Error::Disallowed` until the previous one reported its `Event::ParamsUpdated`, and `Error::UnsupportedRemote` for a
  central without the connection parameters request procedure, for which the host sends the L2CAP request.
- **Data length extension** (feature `data-length`, nRF52832 only): payloads of up to 251 octets each way instead of 27.
  The link layer receives 251 octets from the start and tells a central that asks (LL_LENGTH_REQ). It sends longer
  packets once the host allows them for the link (`Link::set_data_length`) or for new links
  (`Link::set_suggested_length`), and then asks the central itself; a longer length only takes effect once the central
  was told and answered, or acknowledged our answer. The host learns the effective lengths from `Event::DataLength`. The
  host's fragments hold up to 251 octets and are sent in fragments as long as the central
  receives, within its time on the air. The CCM runs in extended length mode and generates its key stream when it is
  armed, as in Zephyr, instead of at radio READY.
- **LE 2M PHY** (nRF52832 only) when the central supports it, which halves the airtime of every packet: the link layer
  asks for it once the link is encrypted and answers the central's own request. Both directions use the same PHY, as the
  radio switches PHYs only while it is disabled.
- **Features and parameters:** once the link is encrypted it asks for the central's features; a connection parameter
  request from the host goes out with the connection parameters request procedure if the central supports it, on an
  encrypted link or not.
- **LE power control:** a central can ask for another transmit power, learns of the link layer's own changes and how far
  it could lower its own power. The transmit power also follows the link on its own: the radio measures the signal of
  every packet from the central and, taking the path as symmetric, lowers the power from 0 dBm in steps down to -20 dBm
  while the central would still hear the device well, and raises it again, up to +4 dBm (by way of +3 dBm on the
  nRF52832), when the signal weakens or the central does not acknowledge a packet; after that it waits 64 packets before
  stepping down. A power a central asked for is kept as a floor for 1024 received packets (about 8 s of traffic at
  7.5 ms); then the link layer decides again and reports each change to a central that asked for reports. Some centrals
  ask for the maximum once and never again. Advertising always uses 0 dBm.
- **Connection events with several packets:** the event goes on while the central or the link layer has more data
  (MD) and another exchange fits before the next event. Received payloads wait in plain text and are handled after
  the event, so the answer within the 150 µs interframe space stays short. A control PDU, a CRC error, a payload
  without room towards the host, a running encryption or termination procedure, or different PHYs per direction
  close the event after the answer.
- **Peripheral latency:** used while nothing is waiting to be sent and no connection or PHY update waits for its
  instant; data from the host ends the skipping at the next connection event. It is also held off, so that every
  connection event is listened to: during the first second of a link, for 200 ms or 8 connection events, whichever is
  longer, after any PDU with a payload in either direction, and while the host asks for it with `Link::hold_latency`.
  Linux reconnects with the latency it stored from the very first event, so without the hold each ATT round trip of a
  reconnection could wait up to the whole latency. The receive window widens with the time
  since the last anchor, up to half the interval less the interframe space.

## Crypto for the host

The host can take its random numbers from the hardware generator ([`rng::fill`](src/rng.rs)) and AES-128 from the
hardware AES ([`encrypt_block`](src/crypto.rs), the ECB). The resolvable private addresses and the identity resolving
keys use the ECB as well. It shares its AES core with the link encryption, which aborts it during a radio event: each
block runs with interrupts off and is retried after an abort, once the link layer has handled the event. The CPU
sleeps until the ECB ends, woken by its pending interrupt; keep the `ECB` interrupt disabled in the NVIC.

## Power

On the nRF52832 the radio uses the fast ramp-up of 40 µs instead of 140 µs, which shortens every receive window and
turnaround by 100 µs. The radio's own interframe timing works only with the slow ramp-up, so TIMER1 times the 150 µs
between two packets as in Zephyr's software switch: PPI channel 4 starts it at the end of a packet, and its compare
enables the radio through PPI channel 5. Pass `TIMER1` to `Radio::new` and keep the `TIMER1` interrupt disabled in the
NVIC. The link layer uses the programmable PPI channels 0, 1, 3, 4 and 5; leave them to it. TIMER0 and TIMER1 are shut
down, not only stopped, between uses, which avoids the standby current of nRF52832 anomaly 78. The nRF51 differs: see
[nRF51](#nrf51).

The high frequency crystal and TIMER0 run only around radio events and RC calibrations. Between events RTC0 keeps the
time and restarts TIMER0 at an exact tick before the next event. During radio events the CPU sleeps with `WFE` inside
the link layer interrupt and wakes only on the radio events and, for the end of a receive window, a TIMER0 compare,
instead of polling them. Their interrupts stay disabled in the NVIC and only mark themselves pending, so keep the
`RADIO` and `TIMER0` interrupts disabled there. Only the short waits for an RTC compare a few ticks ahead also wake on
the RTC tick (30.5 µs).

The crystal starts 800 µs before TIMER0 at first. That lead then follows the crystal: 2 µs shorter after each restart
whose crystal already ran 100 µs before it, 100 µs longer after one whose crystal was late, within 300 to 1500 µs, so
about 2 % of restarts find it late. On the nRF51 it starts at 1500 µs and may grow to 2500 µs. A late crystal costs no
event: TIMER0 starts 300 µs before the radio. The 10 s connection report shows the lead.

The random delay of each advertising event and the entropy of each encryption start come from the RNG interrupt while
other tasks run: bind and enable `RNG` to `rng::on_interrupt`.

The RC oscillator is calibrated when the temperature changed by 0.5 °C, at the latest every 8 s: PPI starts the
calibration once the crystal runs and the clock interrupt reports the end, so the CPU wakes twice instead of polling.
The link layer counts on 500 ppm for its own sleep clock. Following the nRF52832 errata, the calibration runs with the
anomaly 192 workaround set, the channel starting it disables itself after the first crystal start event, which may come
twice (anomaly 201), and the crystal counts as running once it reported its start, without reading `HFCLKSTAT`. The
channel capturing the timer at an RTC tick disables itself after the first compare event too, which may also come twice
(anomaly 179). `clock::calibrate_rc` takes the `TEMP` peripheral and is driven by interrupts only: bind and enable
`TEMP` to `clock::on_temperature_interrupt` and `CLOCK_POWER` to `clock::on_clock_interrupt`, or it waits forever for
its first temperature. A calibration whose crystal or end does not come within 100 ms is retried at the next interval.
Dropping the calibration future releases the crystal. The crystal is shared through a reference count that changes with
its start and stop task in one critical section, and a connection event that finds the crystal stopped starts it again
before it listens.

Run the link layer in an interrupt executor above every other task, so nothing can delay its answer within the 150 µs
interframe space.

## nRF51

Build with `default-features = false, features = ["nrf51"]`. Without `default-features = false` the build stops in
nrf-pac's build script with "Multiple nrfxx Cargo features enabled", as both chips are then enabled. The nRF51 is a
16 MHz Cortex-M0 with 16 or 32 KB of RAM, and its radio lacks parts of the nRF52832's:

- **Not available:** LE 2M (the link layer neither claims nor asks for it, answers a central's PHY request as unknown,
  refuses a `Link::set_phy` or `Link::set_default_phy` that names LE 2M or LE Coded with `Error::Unsupported`, and
  completes a `Link::set_phy` for LE 1M at once), the data length extension (the CCM encrypts 27 octets at most;
  `data-length` does not build for the nRF51), the fast ramp-up, and +3 dBm: the power steps through -20, -16, -12,
  -8, -4, 0 and +4 dBm.
- **Turnarounds:** the radio's own interframe timing, with the shortcuts from the end of a packet over the disabled
  state to the next TXEN or RXEN, as Nordic's nRF51 SoftDevices and Zephyr do. `Radio::new` takes only `RADIO`; TIMER1,
  TIMER2 and the PPI channels 4 and 5 stay free. The link layer uses the programmable PPI channels 0, 1 and 3, and 9 and
  11 in place of the FORK registers the nRF51 lacks.
- **Ramp-up:** about 140 µs. Each receive window opens about 100 µs earlier than on the nRF52832, which costs a little
  more receive current per connection event.
- **Radio trim:** after powering the radio the link layer copies its BLE 1 Mbit trim values from FICR when FICR asks
  for it.
- **Clocks:** the firmware tells the link layer which crystals the board has, with `Clock::with_config`, before
  anything else starts the high frequency crystal: keep Embassy's `hfclk_source` internal. `Clock::new` takes the
  defaults, a 16 MHz crystal and the RC oscillator. `calibrate_rc` waits until either has run, so it may be spawned
  before the clock is created: it starts the crystal only once its frequency is set.

  ```rust
  use nrf_ble::clock::{self, Clock, HighFrequency, LowFrequency};
  let config = clock::Config::new()
      .high_frequency(HighFrequency::Mhz32)
      .low_frequency(LowFrequency::Crystal { ppm: 50 });
  let clock = Clock::with_config(p.TIMER0, p.RTC0, config);
  ```

  The crystal frequency goes to `CLOCK.XTALFREQ`, whose reset value comes from `UICR.XTALFREQ`. With the RC oscillator
  `calibrate_rc` runs as on the nRF52832 and the link layer counts on 500 ppm; with a 32.768 kHz crystal, which the
  firmware starts through Embassy's `lfclk_source`, it counts on the accuracy given, and `calibrate_rc` waits forever
  without calibrating.
- **Interrupts:** bind the link layer's interrupt executor to `SWI0` (there is no `EGU0_SWI0`). The Cortex-M0 has two
  priority bits, but Embassy builds the nRF51 with three, so `P0` and `P1`, `P2` and `P3`, `P4` and `P5`, and `P6` and
  `P7` are the same level: the link layer must be in a higher pair than everything else, such as `P2` over `P4` or `P1`
  over `P2`, not `P2` over `P3`.
- **RAM:** without the data length extension a `Connection` takes 1040 bytes, `link::Shared` 840 and the link layer
  task's future 1840 on thumbv6m (nrf-ll with HCI: 1224, 1040 and 2024), with packet buffers of 40 bytes.
- **Errata:** the nRF52832 workarounds are not applied. Of the nRF51's, only the sign of the temperature is fixed;
  the others wait for the nRF51802 errata document (see `src/chip/nrf51.rs`).
- **Timing, unverified:** the answer within the 150 µs interframe space, with its CCM encryption, and the scan request
  checks of the advertiser get about 2,200 cycles of the 16 MHz CPU, a quarter of the nRF52832's. Measure the slack on
  hardware before relying on encrypted links and scan responses; the ramp-up time is still to be confirmed against the
  nRF51802 product specification. The power control's 12 dB between stepping down and up assumes the nRF52832's RSSI
  accuracy; the nRF51's is coarser and may make the power step back and forth (see `src/power_control.rs`).

Embassy assumes 128 KB of flash on the nRF51, so its `Nvmc` cannot write the upper half of an nRF51802's 256 KB.

## Using it

```toml
[dependencies]
nrf-ble = { path = "../nrf-ble" }
# On an nRF51:
# nrf-ble = { path = "../nrf-ble", default-features = false, features = ["nrf51"] }
```

Enable the `defmt` feature for logs, and on the nRF52832 `data-length` for payloads of up to 251 octets. That feature
costs about 1.5 KB more static RAM, which on the nRF52832 comes out of the stack; without it the link layer answers a
central's data length request with the 27-octet default. The crate follows Embassy's main branch: patch the Embassy
crates to it as in [`Cargo.toml`](Cargo.toml).

## Checks

The spotlight_rust repository builds for thumbv6m-none-eabi by default; this crate's own `.cargo/config.toml` sets the
host as the default target again, so `cargo test` runs on the PC.

```sh
cargo test                                         # host tests, also with --features data-length
cargo test --no-default-features --features nrf51  # host tests for the nRF51
cargo clippy --target thumbv7em-none-eabihf        # lints, also with --features defmt and data-length
cargo clippy --target thumbv6m-none-eabi --no-default-features --features nrf51   # also with defmt
cargo build --release --target thumbv7em-none-eabihf
cargo build --release --target thumbv6m-none-eabi --no-default-features --features nrf51
cargo fmt --check
cargo doc --no-deps                                # rustdoc lints are errors too
```

Clippy runs on the library for the chip targets, as in nrf-ll. The tests are not linted (`cargo clippy --all-targets`
fails on the test code under the `restriction` group, as in nrf-ll).

## License

MIT or Apache-2.0, at your option.
