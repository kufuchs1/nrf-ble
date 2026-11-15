//! The LE signalling channel (CID 5).
//!
//! [`Signalling`] sends the Connection Parameter Update Request and takes its
//! response. The request asks for a [`crate::link::ParamRange`], which is to
//! be the same constant as the Peripheral Preferred Connection Parameters
//! characteristic ([`crate::host::gatt::ppcp`]), so `BlueZ` never finds the two
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
//!
//! With the feature `eatt`, the commands of the credit based channels go to
//! `host::ecfc` (`Action::Ecfc`): the Credit Based Connection and
//! Reconfigure Requests, the Flow Control Credit Indication, a Disconnection
//! Request whose destination is one of our bearers' CIDs, a Disconnection
//! Response, and a Command Reject other than of our pending parameter request,
//! which may reject one of our Disconnection Requests. The identifiers of all
//! our requests then come from one counter (`Signalling::next_identifier`),
//! and the parameter request's own is kept, so that only its response matches
//! it.

#[cfg(feature = "eatt")] use crate::host::ecfc;
use crate::{link::ParamRange, pdu::concat_into};

/// Code of a Command Reject.
pub const COMMAND_REJECT: u8 = 0x01;
/// Code of a Disconnection Request.
pub const DISCONNECTION_REQUEST: u8 = 0x06;
/// Code of a Disconnection Response.
#[cfg(feature = "eatt")]
pub const DISCONNECTION_RESPONSE: u8 = 0x07;
/// Code of a Flow Control Credit Indication.
#[cfg(feature = "eatt")]
pub const FLOW_CONTROL_CREDIT_IND: u8 = 0x16;
/// Code of a Credit Based Connection Request.
#[cfg(feature = "eatt")]
pub const CREDIT_BASED_CONNECTION_REQUEST: u8 = 0x17;
/// Code of a Credit Based Connection Response.
#[cfg(feature = "eatt")]
pub const CREDIT_BASED_CONNECTION_RESPONSE: u8 = 0x18;
/// Code of a Credit Based Reconfigure Request.
#[cfg(feature = "eatt")]
pub const CREDIT_BASED_RECONFIGURE_REQUEST: u8 = 0x19;
/// Code of a Credit Based Reconfigure Response.
#[cfg(feature = "eatt")]
pub const CREDIT_BASED_RECONFIGURE_RESPONSE: u8 = 0x1A;
/// Code of a Connection Parameter Update Request.
pub const CONNECTION_PARAMETER_UPDATE_REQUEST: u8 = 0x12;
/// Code of a Connection Parameter Update Response.
pub const CONNECTION_PARAMETER_UPDATE_RESPONSE: u8 = 0x13;
/// Command Reject reason: command not understood.
pub const REJECT_NOT_UNDERSTOOD: u16 = 0x0000;
/// Command Reject reason: invalid CID in the request.
pub const REJECT_INVALID_CID: u16 = 0x0002;
/// Length of a command header: code, identifier and data length.
pub const HEADER_LEN: usize = 4;
/// Codes of the responses of the signalling channels: Command Reject,
/// Connection, Configuration, Disconnection, Echo and Information Response,
/// Connection Parameter Update Response, LE Credit Based Connection
/// Response, Credit Based Connection and Reconfigure Response.
const RESPONSES: [u8; 10] = [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x13, 0x15, 0x18, 0x1A];
/// Largest command the host sends: a Connection Parameter Update Request.
const COMMAND_MAX: usize = HEADER_LEN.strict_add(8);

/// What a received command asks of the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Action {
    /// A command of the credit based channels, for
    /// [`crate::host::ecfc::Ecfc::command`] with the data after the header.
    #[cfg(feature = "eatt")]
    Ecfc {
        /// The command's code.
        code:       u8,
        /// The command's identifier.
        identifier: u8,
    },
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
    /// The identifier of our last Connection Parameter Update Request.
    #[cfg(feature = "eatt")]
    asked:      u8,
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
        let mut data: [u8; COMMAND_MAX] = [0; COMMAND_MAX];
        let len = concat_into(&mut data[HEADER_LEN..], parts);
        let [len0, len1] = len.saturating_cast::<u16>().to_le_bytes();
        data[..HEADER_LEN].copy_from_slice(&[code, identifier, len0, len1]);
        Self { data, len: HEADER_LEN.saturating_add(len).saturating_cast() }
    }

    /// A Credit Based Reconfigure Response to the request with `identifier`,
    /// with `result`.
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the command is only built"]
    pub fn reconfigure_response(identifier: u8, result: u16) -> Self {
        Self::new(CREDIT_BASED_RECONFIGURE_RESPONSE, identifier, &[&result.to_le_bytes()])
    }

    /// A Command Reject of the request with `identifier` for `reason`, with
    /// `data`.
    fn reject(identifier: u8, reason: u16, data: &[u8]) -> Self {
        Self::new(COMMAND_REJECT, identifier, &[&reason.to_le_bytes(), data])
    }

    /// A Command Reject, invalid CID, of the Disconnection Request with
    /// `identifier` for the channel of `dcid` and `scid`.
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the command is only built"]
    pub fn reject_cid(identifier: u8, dcid: u16, scid: u16) -> Self {
        let [dcid0, dcid1] = dcid.to_le_bytes();
        let [scid0, scid1] = scid.to_le_bytes();
        Self::reject(identifier, REJECT_INVALID_CID, &[dcid0, dcid1, scid0, scid1])
    }
}

impl Signalling {
    /// The identifier of our last Connection Parameter Update Request.
    #[cfg(feature = "eatt")]
    const fn asked(self) -> u8 { self.asked }

    /// The identifier of our last Connection Parameter Update Request: that
    /// of our last request.
    #[cfg(not(feature = "eatt"))]
    const fn asked(self) -> u8 { self.identifier }

    /// Gives up waiting for the response to our request, as after its 30 s
    /// timeout; a late response is then dropped.
    #[inline]
    pub const fn cancel(&mut self) { self.pending = false; }

    /// Whether the command with `code`, `identifier` and `data` is one of
    /// the credit based channels.
    #[cfg(feature = "eatt")]
    const fn is_ecfc(self, code: u8, identifier: u8, data: &[u8]) -> bool {
        match (code, data) {
            (
                DISCONNECTION_RESPONSE
                | FLOW_CONTROL_CREDIT_IND
                | CREDIT_BASED_CONNECTION_REQUEST
                | CREDIT_BASED_RECONFIGURE_REQUEST,
                _,
            ) => true,
            (DISCONNECTION_REQUEST, &[dcid0, dcid1, _, _]) => {
                ecfc::bearer(u16::from_le_bytes([dcid0, dcid1])).is_some()
            },
            (COMMAND_REJECT, _) => !self.pending || identifier != self.asked(),
            _ => false,
        }
    }

    /// A link without signalling so far.
    #[inline]
    #[must_use = "the channel is only built"]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "eatt")]
            asked: 0,
            identifier: 0,
            pending: false,
        }
    }

    /// The identifier for our next command of the credit based channels, a
    /// Disconnection Request or a Flow Control Credit Indication: one more
    /// than the last of any request, from 1 to 255, as 0 is never valid.
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the identifier is to be sent"]
    pub const fn next_identifier(&mut self) -> u8 {
        self.identifier = self.identifier.checked_add(1).unwrap_or(1);
        self.identifier
    }

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
        #[cfg(feature = "eatt")]
        if self.is_ecfc(code, identifier, data) {
            return Some(Action::Ecfc { code, identifier });
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
        // With `eatt` our Disconnection Requests advance the identifier too,
        // so the request's own is kept for its response.
        #[cfg(feature = "eatt")]
        let identifier = {
            self.asked = self.identifier;
            self.asked
        };
        #[cfg(not(feature = "eatt"))]
        let identifier = self.identifier;
        Some(Command::new(CONNECTION_PARAMETER_UPDATE_REQUEST, identifier, &[
            &range.interval_min.to_le_bytes(),
            &range.interval_max.to_le_bytes(),
            &range.latency.to_le_bytes(),
            &range.timeout.to_le_bytes(),
        ]))
    }

    /// The outcome a response gives our request, if it answers it.
    const fn response(&mut self, code: u8, identifier: u8, data: &[u8]) -> Option<Outcome> {
        if !self.pending || identifier != self.asked() {
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
