//! The LE signalling channel (CID 5).
//!
//! [`Signalling`] sends the Connection Parameter Update Request and takes its
//! response. The request asks for a [`crate::link::ParamRange`], which is to
//! be the same constant as the Peripheral Preferred Connection Parameters
//! characteristic ([`crate::host::gatt::ppcp`]), so BlueZ never finds the two
//! disagreeing.
//!
//! A request it does not serve is answered with a Command Reject (Core, Vol
//! 3, Part A, 4.1): reason 0x0000 without data, or, for a Disconnection
//! Request, which names a channel that does not exist, reason 0x0002 with the
//! request's destination and source CID. A response or a Command Reject is
//! never answered. A Command Reject with the identifier of our request
//! rejects it; any other response, and any command with identifier 0 or a
//! length field that does not match the PDU, is dropped, as Linux drops them.
//! The LE signalling channel carries one command per PDU.

use crate::link::ParamRange;

/// Code of a Command Reject.
pub const COMMAND_REJECT: u8 = 0x01;
/// Code of a Disconnection Request.
pub const DISCONNECTION_REQUEST: u8 = 0x06;
/// Code of a Connection Parameter Update Request.
pub const CONNECTION_PARAMETER_UPDATE_REQUEST: u8 = 0x12;
/// Code of a Connection Parameter Update Response.
pub const CONNECTION_PARAMETER_UPDATE_RESPONSE: u8 = 0x13;
/// Command Reject reason: command not understood.
pub const REJECT_NOT_UNDERSTOOD: u16 = 0x0000;
/// Command Reject reason: invalid CID in the request.
pub const REJECT_INVALID_CID: u16 = 0x0002;
/// Length of a command header: code, identifier and data length.
const HEADER_LEN: usize = 4;
/// Codes of the responses of the signalling channels: Command Reject,
/// Connection, Configuration, Disconnection, Echo and Information Response,
/// Connection Parameter Update Response, LE Credit Based Connection
/// Response, Credit Based Connection and Reconfigure Response.
const RESPONSES: [u8; 10] = [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x13, 0x15, 0x18, 0x1A];
/// Largest command the host sends: a Connection Parameter Update Request.
const COMMAND_MAX: usize = HEADER_LEN + 8;

/// What a received command asks of the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Action {
    /// The outcome of our Connection Parameter Update Request.
    Outcome(Outcome),
    /// Send this command in answer.
    Reply(Command),
}

/// One signalling command to send, the payload of a PDU on CID 5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Command {
    /// The command, of which the first `len` octets count.
    data: [u8; COMMAND_MAX],
    /// Its length.
    len:  u8,
}

/// The outcome of a Connection Parameter Update Request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Outcome {
    /// The central accepted the parameters; the link layer reports the
    /// update once it took place.
    Accepted,
    /// The central rejected them, with a response or a Command Reject.
    Rejected,
}

/// The signalling channel of one link.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Signalling {
    /// The identifier of the last request sent.
    identifier: u8,
    /// Whether our request waits for its response.
    pending:    bool,
}

impl Command {
    /// The command for the PDU's payload.
    #[inline]
    #[must_use = "the command is only read"]
    pub const fn bytes(&self) -> &[u8] { self.data.get(..usize::from(self.len)).unwrap_or_default() }

    /// A command with `code`, `identifier` and the data `parts` in order.
    fn new(code: u8, identifier: u8, parts: &[&[u8]]) -> Self {
        let mut data = [0_u8; COMMAND_MAX];
        let mut len = HEADER_LEN;
        for &byte in parts.iter().flat_map(|part| part.iter()) {
            if let Some(slot) = data.get_mut(len) {
                *slot = byte;
                len = len.saturating_add(1);
            }
        }
        let [len0, len1] = u16::try_from(len.saturating_sub(HEADER_LEN)).unwrap_or_default().to_le_bytes();
        if let Some(header) = data.first_chunk_mut::<HEADER_LEN>() {
            *header = [code, identifier, len0, len1];
        }
        Self { data, len: u8::try_from(len).unwrap_or_default() }
    }

    /// A Command Reject of the request with `identifier` for `reason`, with
    /// `data`.
    fn reject(identifier: u8, reason: u16, data: &[u8]) -> Self {
        Self::new(COMMAND_REJECT, identifier, &[&reason.to_le_bytes(), data])
    }
}

impl Signalling {
    /// Gives up waiting for the response to our request, as after its 30 s
    /// timeout; a late response is then dropped.
    #[inline]
    pub const fn cancel(&mut self) { self.pending = false; }

    /// A link without signalling so far.
    #[inline]
    #[must_use = "the channel is only built"]
    pub const fn new() -> Self { Self { identifier: 0, pending: false } }

    /// Whether our request waits for its response.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn pending(&self) -> bool { self.pending }

    /// Takes a received PDU of the channel and returns what it asks of the
    /// host, if anything.
    #[inline]
    #[must_use = "the answer is only computed"]
    pub fn receive(&mut self, pdu: &[u8]) -> Option<Action> {
        let (&[code, identifier, len0, len1], data) = pdu.split_first_chunk::<HEADER_LEN>()?;
        if identifier == 0 || usize::from(u16::from_le_bytes([len0, len1])) != data.len() {
            return None;
        }
        if RESPONSES.contains(&code) {
            return self.response(code, identifier, data).map(Action::Outcome);
        }
        let reply = match (code, data) {
            (DISCONNECTION_REQUEST, &[dcid0, dcid1, scid0, scid1]) => {
                Command::reject(identifier, REJECT_INVALID_CID, &[dcid0, dcid1, scid0, scid1])
            },
            _ => Command::reject(identifier, REJECT_NOT_UNDERSTOOD, &[]),
        };
        Some(Action::Reply(reply))
    }

    /// A Connection Parameter Update Request for `range`, `None` while the
    /// previous one waits for its response.
    #[inline]
    #[must_use = "the request is only built"]
    pub fn request_params(&mut self, range: ParamRange) -> Option<Command> {
        if self.pending {
            return None;
        }
        // Identifiers run from 1 to 255: 0 is never valid.
        self.identifier = self.identifier.checked_add(1).unwrap_or(1);
        self.pending = true;
        Some(Command::new(CONNECTION_PARAMETER_UPDATE_REQUEST, self.identifier, &[
            &range.interval_min.to_le_bytes(),
            &range.interval_max.to_le_bytes(),
            &range.latency.to_le_bytes(),
            &range.timeout.to_le_bytes(),
        ]))
    }

    /// The outcome a response gives our request, if it answers it.
    const fn response(&mut self, code: u8, identifier: u8, data: &[u8]) -> Option<Outcome> {
        if !self.pending || identifier != self.identifier {
            return None;
        }
        let outcome = match (code, data) {
            (CONNECTION_PARAMETER_UPDATE_RESPONSE, &[0, 0]) => Outcome::Accepted,
            (CONNECTION_PARAMETER_UPDATE_RESPONSE, &[_, _]) | (COMMAND_REJECT, &[_, _, ..]) => Outcome::Rejected,
            _ => return None,
        };
        self.pending = false;
        Some(outcome)
    }
}

#[cfg(test)] mod tests;
