//! The link layer task: advertises as the host configured it and runs the
//! resulting connection.

#[cfg(feature = "extended-advertising")]
use crate::advertiser::Setup;
use crate::{
    advertiser::{self, Accepted, Counters, Settings},
    clock::{Clock, Micros, SETUP},
    connection::{Connection, Ended},
    health,
    link::{ConnectionParams, Event, Shared},
    maintenance,
    radio::{PacketBuffer, Radio},
    rng,
};
use core::ops::Deref;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant};

/// Upper bound of the random delay added to each advertising interval.
const ADV_DELAY_MAX_US: u32 = 10_000;
/// Duration of high duty cycle directed advertising.
const HIGH_DUTY_DURATION: Duration = Duration::from_millis(1280);
/// Interval of high duty cycle directed advertising events.
const HIGH_DUTY_INTERVAL_US: Micros = Micros(3750);

/// The link layer task's copy of the advertising settings for one pass of
/// its loop. The identity resolving keys of the copy are overwritten when it
/// is dropped: after the advertising event, before the sleep to the next
/// one, or before a connection runs, as the host's resolving list keeps
/// them.
struct Taken<'settings>(&'settings mut Settings);

impl Deref for Taken<'_> {
    type Target = Settings;

    fn deref(&self) -> &Settings { self.0 }
}

impl Drop for Taken<'_> {
    fn drop(&mut self) { self.0.resolving.clear(); }
}

/// Ends high duty cycle directed advertising after its time. `since` is
/// when the advertising was enabled. Returns true if it ended.
async fn check_limits(settings: &Settings, since: &mut Option<Instant>, shared: &Shared) -> bool {
    let started = *since.get_or_insert_with(Instant::now);
    if !settings.kind.is_high_duty() || started.elapsed() < HIGH_DUTY_DURATION {
        return false;
    }
    *since = None;
    shared.stop_advertising();
    if matches!(
        select(shared.push_event(Event::AdvertisingTimeout), shared.reset_requested()).await,
        Either::Second(())
    ) {
        shared.signal_reset();
    }
    true
}

/// Time until the next advertising event. The random delay comes from the
/// RNG interrupt while other tasks run.
async fn interval(settings: &Settings) -> Micros {
    if settings.kind.is_high_duty() {
        return HIGH_DUTY_INTERVAL_US;
    }
    let mut jitter: [u8; 2] = [0; 2];
    rng::fill_async(&mut jitter).await;
    Micros(settings.interval.saturating_add(u32::from(u16::from_le_bytes(jitter)).strict_rem(ADV_DELAY_MAX_US)))
}

/// Publishes the PHY of a link that starts after an `AUX_CONNECT_REQ`, the
/// secondary channel's both ways, and logs how it starts. Call it after the
/// link was recorded as connected, which resets the PHY to LE 1M.
#[cfg(feature = "extended-advertising")]
fn start_after_aux(setup: Setup, shared: &Shared) {
    shared.set_phys(setup.phy.hci(), setup.phy.hci());
    info!("connection from AUX_CONNECT_REQ: window +{} us, csa2, phy {}M", setup.window_delay_us, setup.phy.hci());
}

/// Runs the link layer forever.
///
/// With `SLOT_GUARD` it checks after each connection event whether the radio
/// received into a buffer it was to send from, and counts it
/// ([`crate::link::Counters::slot_overruns`]): for a firmware that reads the
/// count, such as a build with its debug port open. Without it that check is
/// not built.
#[inline]
pub async fn run<const SLOT_GUARD: bool>(radio: &mut Radio<'_>, clock: &mut Clock<'_>, shared: &Shared) -> ! {
    let mut rx = PacketBuffer::ZERO;
    let mut since = None;
    let mut counters = Counters::new();
    loop {
        health::checkpoint(15);
        maintenance::service(clock, radio).await;
        health::checkpoint(15);
        if shared.take_reset() {
            radio.disable();
            clock.pause();
            shared.complete_reset();
        }
        shared.refresh_private_address();
        #[cfg(not(feature = "extended-advertising"))]
        let mut current = shared.advertising();
        #[cfg(feature = "extended-advertising")]
        let mut current = shared.renewed_advertising().await;
        // Used in place, so the one copy with the keys is the one wiped.
        let Some(settings) = current.as_mut().map(Taken) else {
            since = None;
            clock.pause();
            health::suspend();
            select(shared.changed(), maintenance::requested()).await;
            continue;
        };
        if check_limits(&settings, &mut since, shared).await {
            continue;
        }
        clock.resume_now().await;
        let (started, event) = advertiser::event(radio, clock, &settings, &mut counters, &mut rx);
        counters.log();
        let Some(Accepted { end, request, setup }) = event else {
            let next = started.after(interval(&settings).await);
            let high_duty = settings.kind.is_high_duty();
            // The sleep, up to an advertising interval, needs no key of the
            // resolving list; the next pass takes the host's again.
            drop(settings);
            // The sleep returns `SETUP_US` early, for a radio start the timer
            // triggers; advertising starts when it returns, so it sleeps that
            // much longer to keep the advertising interval. High duty cycle
            // directed advertising keeps the early start instead: its events
            // must be at most 3.75 ms apart, which the loop's own time would
            // otherwise exceed.
            let wake = if high_duty { next } else { next.after(SETUP) };
            if !clock.sleep_until(wake, shared.changed()).await {
                since = None;
            }
            continue;
        };
        shared.set_connected(true);
        radio.set_access_address(request.access_address);
        radio.set_crc_init(request.crc_init);
        let mut connection = Connection::new(&request, end, setup);
        connection.set_preferred_phys(shared.preferred_phys());
        #[cfg(feature = "nrf52833")]
        connection.set_max_power(shared.max_power());
        connection.set_suggested_length(shared.suggested_length());
        let central = request.central();
        let mut shown = central.address;
        shown.reverse();
        info!("central {=[u8; 6]:02X} random {}", shown, central.random);
        #[cfg(feature = "extended-advertising")]
        start_after_aux(setup, shared);
        let params = ConnectionParams::new(request.interval, request.latency, request.timeout);
        let answered = (request.sca, settings.kind.is_directed());
        let epoch = shared.set_info((central, settings.resolve(central), settings.own), params, answered);
        // The link needs no key of the resolving list.
        drop(settings);
        connection.notify(Event::Connected(epoch), shared);
        since = None;
        let (ended, stats) = connection.run::<SLOT_GUARD>(radio, clock, &mut rx, shared).await;
        info!(
            "connection ended: {} events, {} missed, {} crc errors, {} packets",
            stats.events, stats.missed, stats.crc_errors, stats.received
        );
        #[cfg(feature = "defmt")]
        stats.log_answers(defmt::intern!("connection ended"));
        if matches!(ended, Ended::Reset) {
            radio.disable();
            clock.pause();
            shared.complete_reset();
            continue;
        }
        // The host gets the retained events and every packet the link
        // acknowledged before it learns that the link ended.
        if !connection.flush_after_disconnect(shared).await
            || matches!(select(shared.acl_in_drained(), shared.reset_requested()).await, Either::Second(()))
        {
            radio.disable();
            clock.pause();
            shared.complete_reset();
            continue;
        }
        let Some(how) = ended.link_end() else { continue };
        let reason = how.reason();
        shared.set_connected(false);
        if matches!(
            select(shared.push_event(Event::Disconnected(reason)), shared.reset_requested()).await,
            Either::Second(())
        ) {
            radio.disable();
            clock.pause();
            shared.complete_reset();
        }
    }
}

#[cfg(test)] mod tests;
