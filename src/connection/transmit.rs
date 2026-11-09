//! The PDUs to send: the control PDU queue and two transmit slots, one
//! holding the PDU on the air until the central acknowledges it, the other
//! the next PDU, prepared and sealed before the event.
//!
//! The answer within the interframe space never copies, seals or searches:
//! on an acknowledgement it only switches to the other slot, or writes an
//! empty PDU there, and patches the header flags (see
//! [`Connection::respond`](super::Connection)). Preparing only peeks at the
//! queue and the host's packet, so it can run again before every event; a
//! PDU leaves them only when it becomes the one on the air.

use super::{
    Connection,
    DATA_BUFFER_LEN,
    DATA_HEADER_LEN,
    ERROR_HARDWARE_FAILURE,
    ERROR_MIC_FAILURE,
    OP_TERMINATE_IND,
    Packet,
    Phase,
    Source,
    Trace,
    TxKind,
    TxSlot,
};
use crate::{crypto, link::Shared, pdu::Llid};

/// Up to `N` items in order, kept in place: taking the first moves no
/// other.
#[derive(Clone, Copy)]
pub(super) struct Ring<Item, const N: usize> {
    /// Index of the first item.
    head:  u8,
    /// The items, from `head` on and around.
    items: [Item; N],
    /// Number of items.
    len:   u8,
}

impl<Item: Copy, const N: usize> Ring<Item, N> {
    /// Forgets every item.
    pub(super) const fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Takes the first item off, if any.
    pub(super) fn drop_front(&mut self) {
        if self.len != 0 {
            self.head = u8::try_from(self.index(1)).unwrap_or(0);
            self.len = self.len.saturating_sub(1);
        }
    }

    /// The first item.
    pub(super) fn front(&self) -> Option<&Item> { self.get(0) }

    /// The first item, to change in place.
    pub(super) fn front_mut(&mut self) -> Option<&mut Item> {
        if self.len == 0 {
            return None;
        }
        self.items.get_mut(usize::from(self.head))
    }

    /// The item `offset` places after the first.
    pub(super) fn get(&self, offset: usize) -> Option<&Item> {
        if offset >= usize::from(self.len) {
            return None;
        }
        self.items.get(self.index(offset))
    }

    /// Whether another item fits.
    pub(super) fn has_room(&self) -> bool { usize::from(self.len) < N }

    /// Storage index of the item `offset` places after the first.
    fn index(&self, offset: usize) -> usize { usize::from(self.head).wrapping_add(offset).checked_rem(N).unwrap_or(0) }

    /// Whether it holds no item.
    pub(super) const fn is_empty(&self) -> bool { self.len == 0 }

    /// Every place, used or not, to overwrite what it held.
    pub(super) const fn items_mut(&mut self) -> &mut [Item; N] { &mut self.items }

    /// Number of items.
    pub(super) fn len(&self) -> usize { usize::from(self.len) }

    /// An empty ring whose places hold `fill`.
    pub(super) const fn new(fill: Item) -> Self { Self { head: 0, items: [fill; N], len: 0 } }

    /// Adds `item` at the end. Returns false if it is full.
    pub(super) fn push(&mut self, item: Item) -> bool {
        let Some(slot) = self.push_mut() else { return false };
        *slot = item;
        true
    }

    /// Adds an item at the end and gives its place, to fill in place.
    pub(super) fn push_mut(&mut self) -> Option<&mut Item> {
        if !self.has_room() {
            return None;
        }
        let index = self.index(usize::from(self.len));
        self.len = self.len.saturating_add(1);
        self.items.get_mut(index)
    }
}

impl TxSlot {
    /// A slot holding an empty PDU.
    pub(super) const fn empty() -> Self {
        let mut plain = [0; DATA_BUFFER_LEN];
        if let Some(header) = plain.first_mut() {
            *header = Llid::Continuation.bits();
        }
        Self {
            encrypted: false,
            kind:      TxKind::Empty,
            plain:     Packet(plain),
            sealed:    Packet([0; DATA_BUFFER_LEN]),
            source:    Source::Empty,
        }
    }

    /// The buffer the radio sends.
    pub(super) const fn on_air(&mut self) -> &mut Packet {
        if self.encrypted { &mut self.sealed } else { &mut self.plain }
    }

    /// Overwrites both buffers once the link ended.
    pub(super) fn wipe(&mut self) {
        crypto::wipe(&mut self.plain.0);
        crypto::wipe(&mut self.sealed.0);
    }
}

impl Trace {
    /// Notes a control PDU, as long as there is room.
    pub(super) fn control(&mut self, sent: bool, opcode: u8) {
        if let Some(entry) = self.controls.get_mut(usize::from(self.count)) {
            *entry = (sent, opcode);
            self.count = self.count.saturating_add(1);
        }
    }
}

#[expect(clippy::multiple_inherent_impl, reason = "the transmit slots live in their own file")]
impl Connection {
    /// Makes the free slot an empty PDU and sends it: the answer to an
    /// acknowledgement when nothing is prepared. Within the interframe
    /// space; the slot is not the one the radio points at. Empty PDUs are
    /// never encrypted, also on an encrypted link.
    pub(super) const fn commit_empty(&mut self) {
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
    pub(super) fn commit_next(&mut self) {
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

    /// The slot of the PDU on the air until the central acknowledges it.
    pub(super) const fn current(&self) -> &TxSlot { self.slot(self.cur) }

    /// The slot of the PDU on the air until the central acknowledges it.
    pub(super) const fn current_mut(&mut self) -> &mut TxSlot { self.slot_mut(self.cur) }

    /// Whether more of ours waits than the prepared PDU: a control PDU, the
    /// host's packet or more of it, or a packet the host queued.
    pub(super) fn more_waiting(&self, shared: &Shared) -> bool {
        !self.queue.is_empty() || self.acl.is_some() || shared.has_acl_out()
    }

    /// Prepares the next PDU in the free slot, between events, or on the
    /// nRF52832 also while our answer goes out: the first control PDU,
    /// otherwise the next fragment of the host's data, which waits while
    /// encryption starts or pauses, otherwise an empty PDU. It copies the
    /// payload and, on an encrypted link, seals it with the next packet
    /// counter, but takes nothing off yet: running it again before the next
    /// event prepares the same PDU, or what came first meanwhile, with the
    /// same counter, as a PDU only uses up its counter once it is sent.
    pub(super) fn prepare_next(&mut self, shared: &Shared) {
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

    /// Slot `second` or the first.
    pub(super) const fn slot(&self, second: bool) -> &TxSlot { if second { &self.slots.1 } else { &self.slots.0 } }

    /// Slot `second` or the first.
    pub(super) const fn slot_mut(&mut self, second: bool) -> &mut TxSlot {
        if second { &mut self.slots.1 } else { &mut self.slots.0 }
    }

    /// Starts the slots of a new link: an empty PDU on the air, and the
    /// first PDU to send in its place, as the link's first answer.
    pub(super) fn start_slots(&mut self, shared: &Shared) {
        self.slots = (TxSlot::empty(), TxSlot::empty());
        self.cur = false;
        self.tx_kind = TxKind::Empty;
        self.prepare_next(shared);
        if self.next_ready {
            self.commit_next();
        }
    }
}
