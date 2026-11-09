//! The turnaround on the nRF51: the radio's own interframe timing. With the
//! END to DISABLE and DISABLED to TXEN or RXEN shortcuts, the radio ramps up
//! right after a packet and starts sending 150 us (TIFS) after its END by
//! itself, as Nordic's nRF51 SoftDevices and Zephyr's nRF51 port do. The
//! nRF51 has only the slow ramp-up, with which this timing works, and keeps
//! TIMER1 and the PPI channels 4 and 5 free.
//!
//! The radio latches the packet pointer when the answer starts, about 140 us
//! after the END of the packet before, and sends whatever it points at then.
//! The pointer is double-buffered: once the access address of the received
//! packet has come, a new pointer applies to the next start only. So the
//! connection points the radio at its unacknowledged PDU right after that
//! access address, and its answer within the interframe space only patches
//! that PDU's header flags or switches to the other, prepared slot, in a few
//! hundred cycles: an answer that comes too late resends the previous PDU
//! with its previous flags, which the central takes as a retransmission,
//! and never echoes the received packet (see `Connection::respond`). The
//! advertiser points the radio at the scan response the same way.

use super::{REGS, Radio, Turnaround};
use core::sync::atomic::{Ordering, compiler_fence};

/// Sets what the radio does after the current packet. A turnaround to send
/// follows a reception, whose signal strength the radio measures; during our
/// own packets it measures nothing, so that a sample of the central's packet
/// stays readable while ours goes out.
#[inline]
pub fn arm(turnaround: Turnaround) {
    let receiving = turnaround == Turnaround::Transmit;
    REGS.shorts().write(|w| {
        w.set_ready_start(true);
        w.set_end_disable(true);
        w.set_address_rssistart(receiving);
        w.set_disabled_rssistop(receiving);
        w.set_disabled_txen(turnaround == Turnaround::Transmit);
        w.set_disabled_rxen(turnaround == Turnaround::Receive);
    });
}

/// Nothing to set up: the radio times its turnarounds itself, with the
/// interframe space the radio driver sets.
#[inline]
pub const fn init() {}

/// Sleeps until the radio was disabled after the packet, which enabled it
/// again through the shortcut, and clears the disabled event.
#[inline]
pub fn wait() {
    Radio::sleep_on(|w| w.set_disabled(true), || REGS.events_disabled().read() != 0);
    REGS.events_disabled().write_value(0);
    compiler_fence(Ordering::SeqCst);
}
