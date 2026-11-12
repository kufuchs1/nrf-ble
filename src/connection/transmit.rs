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

use super::{DATA_BUFFER_LEN, Packet, Source, Trace, TxKind, TxSlot};
use crate::{crypto, pdu::Llid};

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
    pub(super) const fn drop_front(&mut self) {
        if self.len != 0 {
            self.head = u8::try_from(self.index(1)).unwrap_or(0);
            self.len = self.len.saturating_sub(1);
        }
    }

    /// The first item.
    pub(super) const fn front(&self) -> Option<&Item> { self.get(0) }

    /// The first item, to change in place.
    pub(super) const fn front_mut(&mut self) -> Option<&mut Item> {
        if self.len == 0 {
            return None;
        }
        self.items.get_mut(usize::from(self.head))
    }

    /// The item `offset` places after the first.
    pub(super) const fn get(&self, offset: usize) -> Option<&Item> {
        if offset >= usize::from(self.len) {
            return None;
        }
        self.items.get(self.index(offset))
    }

    /// Whether another item fits.
    pub(super) const fn has_room(&self) -> bool { usize::from(self.len) < N }

    /// Storage index of the item `offset` places after the first.
    const fn index(&self, offset: usize) -> usize {
        usize::from(self.head).wrapping_add(offset).checked_rem(N).unwrap_or(0)
    }

    /// Whether it holds no item.
    pub(super) const fn is_empty(&self) -> bool { self.len == 0 }

    /// Every place, used or not, to overwrite what it held.
    pub(super) const fn items_mut(&mut self) -> &mut [Item; N] { &mut self.items }

    /// Number of items.
    pub(super) const fn len(&self) -> usize { usize::from(self.len) }

    /// An empty ring whose places hold `fill`.
    pub(super) const fn new(fill: Item) -> Self { Self { head: 0, items: [fill; N], len: 0 } }

    /// Adds `item` at the end. Returns false if it is full.
    pub(super) const fn push(&mut self, item: Item) -> bool {
        let Some(slot) = self.push_mut() else { return false };
        *slot = item;
        true
    }

    /// Adds an item at the end and gives its place, to fill in place.
    pub(super) const fn push_mut(&mut self) -> Option<&mut Item> {
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
    pub(super) const fn control(&mut self, sent: bool, opcode: u8) {
        if let Some(entry) = self.controls.get_mut(usize::from(self.count)) {
            *entry = (sent, opcode);
            self.count = self.count.saturating_add(1);
        }
    }
}
