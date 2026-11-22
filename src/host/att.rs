//! The attribute protocol, as a server.
//!
//! Its ATT MTU is the default of 23 octets, or with the feature `att-mtu` one
//! of up to 65 that the client agrees to.
//!
//! [`Server`] decodes the requests `BlueZ` sends, answers them from the GATT
//! table ([`crate::host::gatt::Db`]) with the error codes of the Core
//! specification, and encodes notifications. A request arrives on a
//! [`Bearer`], whose ATT MTU bounds its response: the fixed channel, or with
//! the feature `eatt` an enhanced bearer, which serves every request but the
//! Exchange MTU (Request Not Supported, 0x06). One request is outstanding on
//! each bearer at a time, so the engine keeps one response slot of
//! [`ATT_MAX`] octets for each. Indications are not sent, Service Changed's
//! included, and a Handle Value Confirmation is ignored on any bearer.
//!
//! It serves exactly these requests:
//!
//! - Exchange MTU: the answer is [`ATT_MAX`], 23 or with `att-mtu` 65. With
//!   `att-mtu` the fixed channel's ATT MTU then becomes the smaller of the
//!   client's and 65, at least 23, from the next PDU on; the response itself
//!   still fits the ATT MTU before it. Notifications still carry at most
//!   [`NOTIFY_MAX`] (20) octets of a value, in a PDU of 23.
//! - Find Information.
//! - Find By Type Value, for primary services (0x2800) only.
//! - Read By Type, for any attribute type: characteristic declarations (0x2803)
//!   are grouped by the size of their UUID, so one response holds entries of
//!   length 7 or 21 only. Includes (0x2802) are not in the table and give
//!   Attribute Not Found (0x0A), as do the Server Supported Features (0x2B3A)
//!   without the feature `eatt`; the Database Hash (0x2B2A) gives the table's
//!   hash.
//! - Read, and Read Blob: an offset equal to the value's length gives an empty
//!   response, a larger one Invalid Offset (0x07), never Attribute Not Long
//!   (0x0B), which would fail `BlueZ`'s whole read.
//! - Read By Group Type for primary services, with the real end handle of the
//!   last service; secondary services (0x2801) give 0x0A, any other type
//!   Unsupported Group Type (0x10).
//! - Write Request and Write Command; Handle Value Confirmation.
//! - With the feature `eatt`, the requests Enhanced ATT makes mandatory:
//!   - Read Multiple Variable Length, for two handles or more. An error names
//!     the first handle with the most important error, in the specification's
//!     order: Insufficient Authentication (0x05), Insufficient Encryption
//!     (0x0F), Invalid Handle (0x01), Read Not Permitted (0x02); then an error
//!     of the application's read. The response is cut after the ATT MTU less 1
//!     octets, or before a length field that would not fit whole.
//!   - Prepare Write and Execute Write, for one value of up to `PREPARE_MAX`
//!     octets: the parts are checked for the write's permission as they come
//!     and queued, each part following the one before it in the same attribute,
//!     and anything else gets Prepare Queue Full (0x09). The Execute Write
//!     writes the value as a Write Request does, or cancels; a queue that does
//!     not start at offset 0 gets Invalid Offset (0x07), as only whole values
//!     are written. The queue is emptied after each Execute Write, and with the
//!     link.
//!   - Writes of the Client Supported Features: octet 0 is kept, bits 0 to 2 of
//!     it, and further octets are ignored; a write that would clear a bit the
//!     client set gets Value Not Allowed (0x13). Reads give one octet, and the
//!     Server Supported Features read `0x01`, EATT Supported.
//!
//!   Multiple Handle Value Notifications (`Server::notify_multiple`) go out
//!   only to a client that set bit 2 of its Client Supported Features.
//!
//! Any other request gets Request Not Supported (0x06); a command (opcode bit
//! 6) is never answered, not even when it fails, and an unexpected response
//! is ignored, as `BlueZ` shuts the bearer down on an unsolicited one. A
//! request with the wrong length gets Invalid PDU (0x04), and a client
//! characteristic configuration write of a length other than 2 Invalid
//! Attribute Value Length (0x0D). Other configuration writes are taken
//! leniently: only the bits the characteristic's properties allow are kept.
//!
//! An attribute that needs encryption is served only for a request that was
//! itself received encrypted ([`crate::link::AclIn::encrypted`]) on a link
//! whose key the host handed to the link layer itself, with
//! [`crate::link::Link::ltk_reply`]; the engine gives that as the security
//! of each request, so the check never depends on the order in which the
//! host learns of the encryption. A request that lacks it gets Insufficient
//! Encryption (0x0F), never Insufficient Authentication (0x05), on which
//! `BlueZ` would ask for pairing with protection against a man in the middle,
//! and Just Works pairing would fail. The table refuses attributes that
//! need authenticated pairing while it is compiled
//! ([`crate::host::gatt::Db::new`]), so the server never sends 0x05.
//!
//! Notifications need the security their characteristic was declared with,
//! also for a characteristic that can be neither read nor written.

use crate::host::gatt::{
    AttError,
    Attr,
    Char,
    DYNAMIC_MAX,
    Db,
    Handler,
    Kind,
    PRIMARY_SERVICE,
    PROP_NOTIFY,
    SECONDARY_SERVICE,
    Sec,
    Subscriptions,
    Uuid,
    Value,
};
#[cfg(feature = "eatt")] use core::mem;

/// The default ATT MTU.
///
/// The least any bearer has, and the fixed channel's until an Exchange MTU
/// raises it (with the feature `att-mtu`).
pub const MTU: usize = 23;
/// The largest ATT MTU the server takes: 65 with the feature `att-mtu`,
/// otherwise [`MTU`].
///
/// The server answers an Exchange MTU Request with it, and a response slot
/// is this long.
pub const ATT_MAX: usize = if cfg!(feature = "att-mtu") { 65 } else { MTU };
/// Longest value a notification carries.
pub const NOTIFY_MAX: usize = MTU.strict_sub(3);
/// Opcode of an Error Response.
pub const ERROR_RESPONSE: u8 = 0x01;
/// Opcode of an Exchange MTU Request.
pub const EXCHANGE_MTU_REQUEST: u8 = 0x02;
/// Opcode of an Exchange MTU Response.
pub const EXCHANGE_MTU_RESPONSE: u8 = 0x03;
/// Opcode of a Find Information Request.
pub const FIND_INFORMATION_REQUEST: u8 = 0x04;
/// Opcode of a Find Information Response.
pub const FIND_INFORMATION_RESPONSE: u8 = 0x05;
/// Opcode of a Find By Type Value Request.
pub const FIND_BY_TYPE_VALUE_REQUEST: u8 = 0x06;
/// Opcode of a Find By Type Value Response.
pub const FIND_BY_TYPE_VALUE_RESPONSE: u8 = 0x07;
/// Opcode of a Read By Type Request.
pub const READ_BY_TYPE_REQUEST: u8 = 0x08;
/// Opcode of a Read By Type Response.
pub const READ_BY_TYPE_RESPONSE: u8 = 0x09;
/// Opcode of a Read Request.
pub const READ_REQUEST: u8 = 0x0A;
/// Opcode of a Read Response.
pub const READ_RESPONSE: u8 = 0x0B;
/// Opcode of a Read Blob Request.
pub const READ_BLOB_REQUEST: u8 = 0x0C;
/// Opcode of a Read Blob Response.
pub const READ_BLOB_RESPONSE: u8 = 0x0D;
/// Opcode of a Read By Group Type Request.
pub const READ_BY_GROUP_TYPE_REQUEST: u8 = 0x10;
/// Opcode of a Read By Group Type Response.
pub const READ_BY_GROUP_TYPE_RESPONSE: u8 = 0x11;
/// Opcode of a Write Request.
pub const WRITE_REQUEST: u8 = 0x12;
/// Opcode of a Write Response.
pub const WRITE_RESPONSE: u8 = 0x13;
/// Opcode of a Handle Value Notification.
pub const NOTIFICATION: u8 = 0x1B;
/// Opcode of a Handle Value Indication.
pub const INDICATION: u8 = 0x1D;
/// Opcode of a Handle Value Confirmation.
pub const CONFIRMATION: u8 = 0x1E;
/// Opcode of a Write Command.
pub const WRITE_COMMAND: u8 = 0x52;
/// Opcode of a Prepare Write Request.
#[cfg(feature = "eatt")]
pub const PREPARE_WRITE_REQUEST: u8 = 0x16;
/// Opcode of a Prepare Write Response.
#[cfg(feature = "eatt")]
pub const PREPARE_WRITE_RESPONSE: u8 = 0x17;
/// Opcode of an Execute Write Request.
#[cfg(feature = "eatt")]
pub const EXECUTE_WRITE_REQUEST: u8 = 0x18;
/// Opcode of an Execute Write Response.
#[cfg(feature = "eatt")]
pub const EXECUTE_WRITE_RESPONSE: u8 = 0x19;
/// Opcode of a Read Multiple Variable Length Request.
#[cfg(feature = "eatt")]
pub const READ_MULTIPLE_VARIABLE_REQUEST: u8 = 0x20;
/// Opcode of a Read Multiple Variable Length Response.
#[cfg(feature = "eatt")]
pub const READ_MULTIPLE_VARIABLE_RESPONSE: u8 = 0x21;
/// Opcode of a Multiple Handle Value Notification.
#[cfg(feature = "eatt")]
pub const MULTIPLE_NOTIFICATION: u8 = 0x23;
/// The Client Supported Features bits the specification defines: Robust
/// Caching (0), Enhanced ATT Bearer (1) and Multiple Handle Value
/// Notifications (2).
#[cfg(feature = "eatt")]
pub const CLIENT_FEATURES: u8 = 0x07;
/// Client Supported Features bit 2: the client takes Multiple Handle Value
/// Notifications.
#[cfg(feature = "eatt")]
pub const MULTIPLE_NOTIFICATIONS: u8 = 0x04;
/// The Server Supported Features: bit 0, EATT Supported.
#[cfg(feature = "eatt")]
pub const SERVER_FEATURES: u8 = 0x01;
/// The longest value the prepare queue takes.
#[cfg(feature = "eatt")]
pub const PREPARE_MAX: usize = 22;
/// Opcode bit of a command, which is never answered.
const COMMAND_FLAG: u8 = 0x40;
/// Opcodes a client sends only as a server, or never: responses,
/// notifications and indications. A server ignores them.
const NOT_REQUESTS: [u8; 16] =
    [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13, 0x17, 0x19, 0x1B, 0x1D, 0x21, 0x23];
/// Format of a Find Information Response with 16-bit UUIDs.
const FORMAT_16: u8 = 0x01;
/// Format of a Find Information Response with 128-bit UUIDs.
const FORMAT_128: u8 = 0x02;
/// Longest value the server builds itself: a characteristic declaration
/// with a 128-bit UUID is 19 octets, a dynamic value up to 22.
const LOCAL_MAX: usize = DYNAMIC_MAX;

/// Why a notification cannot be sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum NotifyError {
    /// The link lacks the security the characteristic needs.
    Insecure,
    /// The client has not enabled it, or the characteristic cannot do it.
    NotSubscribed,
    /// The value is longer than [`NOTIFY_MAX`]; for a Multiple Handle Value
    /// Notification, the values do not fit one PDU of [`MTU`] octets.
    TooLong,
    /// A Multiple Handle Value Notification for a client that has not set
    /// bit 2 of its Client Supported Features ([`MULTIPLE_NOTIFICATIONS`]),
    /// or of fewer than two values.
    #[cfg(feature = "eatt")]
    Unsupported,
}

/// The ATT bearer a request arrives on, which sets the ATT MTU of its
/// response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Bearer {
    /// An enhanced bearer of Enhanced ATT (`crate::host::ecfc`), with the
    /// feature `eatt`: its ATT MTU is fixed when the channel opens, the
    /// smaller of its MTU and the peer's, at least [`MTU`] and at most
    /// [`ATT_MAX`]. It serves no Exchange MTU.
    #[cfg(feature = "eatt")]
    Enhanced {
        /// The ATT MTU.
        mtu: usize,
    },
    /// The fixed channel of the attribute protocol, CID 0x0004, whose
    /// ATT MTU is [`MTU`] until an Exchange MTU raises it, with the feature
    /// `att-mtu`.
    Fixed,
}

/// The values of Prepare Write Requests that wait for the Execute Write
/// Request: consecutive parts of one attribute's value, one queue for each
/// client.
#[cfg(feature = "eatt")]
#[derive(Clone, Copy, Debug)]
struct Prepared {
    /// The queued octets, of which the first `len` count.
    bytes:  [u8; PREPARE_MAX],
    /// The attribute's handle, 0 while nothing is queued.
    handle: u16,
    /// The number of octets queued.
    len:    u8,
    /// The offset in the value of the first octet queued.
    offset: u16,
}

/// The attribute server of one link: the table and the link's client
/// characteristic configuration.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Server {
    /// The client's Client Supported Features, bits 0 to 2.
    #[cfg(feature = "eatt")]
    client_features: u8,
    /// The table.
    db:              &'static Db,
    /// The fixed channel's ATT MTU: [`MTU`] until an Exchange MTU.
    #[cfg(feature = "att-mtu")]
    mtu:             u16,
    /// The prepare queue.
    #[cfg(feature = "eatt")]
    prepared:        Prepared,
    /// The link's client characteristic configuration.
    subscriptions:   Subscriptions,
}

/// An Error Response to give: the handle it names and its code.
type Failure = (u16, AttError);

/// The length of the response written, or the error to answer with.
type Answer = Result<usize, Failure>;

/// A value as it is read: constant bytes, bytes built for the read, or
/// zeros.
#[derive(Clone, Copy)]
enum Source {
    /// Bytes built for the read.
    Local {
        /// The bytes, of which the first `len` count.
        bytes: [u8; LOCAL_MAX],
        /// Their number.
        len:   usize,
    },
    /// Constant bytes.
    Static(&'static [u8]),
    /// This many zeros.
    Zeros(usize),
}

/// Writes a response into the slot, refusing what does not fit.
struct Writer<'out> {
    /// The response slot, as long as the bearer's ATT MTU.
    buf: &'out mut [u8],
    /// Octets written.
    len: usize,
}

impl Server {
    /// Takes the client's ATT MTU of an Exchange MTU Request, `params`:
    /// the fixed channel's becomes the smaller of it and [`ATT_MAX`], at
    /// least [`MTU`]. A request of the wrong length changes nothing.
    #[cfg(feature = "att-mtu")]
    const fn agree_mtu(&mut self, params: &[u8]) {
        if let &[client0, client1] = params {
            self.mtu = u16::from_le_bytes([client0, client1])
                .clamp(MTU.saturating_cast::<u16>(), ATT_MAX.saturating_cast::<u16>());
        }
    }

    /// The client's Client Supported Features, bits 0 to 2: written on this
    /// link, or restored from the bond ([`Self::restore_client_features`]).
    #[cfg(feature = "eatt")]
    #[inline]
    #[must_use = "the features are only read"]
    pub const fn client_features(&self) -> u8 { self.client_features }

    /// Answers an Exchange MTU Request: always [`ATT_MAX`].
    const fn exchange_mtu(params: &[u8], out: &mut [u8]) -> Answer {
        if params.len() != 2 {
            return Err((0, AttError::INVALID_PDU));
        }
        let [low, high] = ATT_MAX.saturating_cast::<u16>().to_le_bytes();
        let mut writer = Writer::new(out, EXCHANGE_MTU_RESPONSE);
        writer.push(&[low, high]);
        Ok(writer.finish())
    }

    /// Answers an Execute Write Request: writes the queued value, with flags
    /// 1, as a Write Request does, or cancels it, with flags 0. Either empties
    /// the queue.
    #[cfg(feature = "eatt")]
    fn execute_write(&mut self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8]) -> Answer {
        let &[flags] = params else { return Err((0, AttError::INVALID_PDU)) };
        if flags > 1 {
            return Err((0, AttError::INVALID_PDU));
        }
        let prepared = mem::replace(&mut self.prepared, Prepared::new());
        if flags == 1 && prepared.handle != 0 {
            if prepared.offset != 0 {
                // Only whole values are written.
                return Err((prepared.handle, AttError::INVALID_OFFSET));
            }
            self.write_value(prepared.handle, prepared.value(), level, app, true)?;
        }
        Ok(Writer::new(out, EXECUTE_WRITE_RESPONSE).finish())
    }

    /// Answers a Find By Type Value Request: primary services with the
    /// given UUID, with their end handles.
    fn find_by_type_value(&self, params: &[u8], out: &mut [u8]) -> Answer {
        let Some((&[start0, start1, end0, end1, type0, type1], value)) = params.split_first_chunk::<6>() else {
            return Err((0, AttError::INVALID_PDU));
        };
        let (start, end) = range([start0, start1], [end0, end1])?;
        if u16::from_le_bytes([type0, type1]) != PRIMARY_SERVICE {
            return Err((start, AttError::ATTRIBUTE_NOT_FOUND));
        }
        let mut writer = Writer::new(out, FIND_BY_TYPE_VALUE_RESPONSE);
        for (handle, attr) in self.within(start, end) {
            if attr.kind() == Kind::Service && attr.uuid().matches(value) {
                let [handle0, handle1] = handle.to_le_bytes();
                let [group0, group1] = self.db.group_end(handle).to_le_bytes();
                if !writer.push(&[handle0, handle1, group0, group1]) {
                    break;
                }
            }
        }
        writer.found(start)
    }

    /// Answers a Find Information Request: the handles and types in the
    /// range, all with UUIDs of the size of the first.
    fn find_information(&self, params: &[u8], out: &mut [u8]) -> Answer {
        let &[start0, start1, end0, end1] = params else { return Err((0, AttError::INVALID_PDU)) };
        let (start, end) = range([start0, start1], [end0, end1])?;
        let mut writer = Writer::new(out, FIND_INFORMATION_RESPONSE);
        let mut size = None;
        for (handle, attr) in self.within(start, end) {
            let uuid = attr.type_uuid();
            if *size.get_or_insert_with(|| uuid.wire_len()) != uuid.wire_len() {
                break;
            }
            if writer.len == 1 {
                writer.push(&[if uuid.wire_len() == 2 { FORMAT_16 } else { FORMAT_128 }]);
            }
            let mut entry: [u8; 18] = [0; 18];
            let [handle0, handle1] = handle.to_le_bytes();
            entry[0] = handle0;
            entry[1] = handle1;
            let len = uuid.write(&mut entry[2..]).saturating_add(2);
            if !writer.push(entry.get(..len).unwrap_or_default()) {
                break;
            }
        }
        writer.found(start)
    }

    /// Answers a request, `pdu`, received on the fixed channel
    /// ([`Bearer::Fixed`]) at the security `level`, as
    /// [`Self::handle_on`] does, into a slot of [`ATT_MAX`] octets, which
    /// any ATT MTU of the channel fits.
    #[inline]
    pub fn handle(&mut self, pdu: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8; ATT_MAX]) -> Option<usize> {
        self.handle_on(Bearer::Fixed, pdu, level, app, out)
    }

    /// Answers a request, `pdu`, received on `bearer` at the security
    /// `level`: open unless it was received encrypted on a link whose key the
    /// host handed to the link layer itself. Writes the response into the
    /// first octets of `slot`, at most the bearer's ATT MTU of them, and
    /// returns its length; `None` for a PDU that gets no response: a
    /// command, a confirmation or a response. A `slot` shorter than the
    /// bearer's ATT MTU is a mistake of the caller: the PDU is then ignored,
    /// and `None` returned.
    #[inline]
    pub fn handle_on(
        &mut self,
        bearer: Bearer,
        pdu: &[u8],
        level: Sec,
        app: &dyn Handler,
        slot: &mut [u8],
    ) -> Option<usize> {
        let mtu = match bearer {
            #[cfg(feature = "att-mtu")]
            Bearer::Fixed => usize::from(self.mtu),
            #[cfg(not(feature = "att-mtu"))]
            Bearer::Fixed => MTU,
            #[cfg(feature = "eatt")]
            Bearer::Enhanced { mtu } => mtu.clamp(MTU, ATT_MAX),
        };
        let out = slot.get_mut(..mtu)?;
        let (&opcode, params) = pdu.split_first()?;
        #[cfg(feature = "eatt")]
        if bearer != Bearer::Fixed && opcode == EXCHANGE_MTU_REQUEST {
            // The ATT MTU of an enhanced bearer is the channel's.
            return Some(error_response(out, opcode, 0, AttError::REQUEST_NOT_SUPPORTED));
        }
        let answer = match opcode {
            EXCHANGE_MTU_REQUEST => {
                // The response goes out within the ATT MTU before it.
                #[cfg(feature = "att-mtu")]
                self.agree_mtu(params);
                Self::exchange_mtu(params, out)
            },
            FIND_INFORMATION_REQUEST => self.find_information(params, out),
            FIND_BY_TYPE_VALUE_REQUEST => self.find_by_type_value(params, out),
            READ_BY_TYPE_REQUEST => self.read_by_type(params, level, app, out),
            READ_REQUEST => self.read(params, level, app, out),
            READ_BLOB_REQUEST => self.read_blob(params, level, app, out),
            READ_BY_GROUP_TYPE_REQUEST => self.read_by_group_type(params, out),
            WRITE_REQUEST => self.write(params, level, app, true).map(|()| Writer::new(out, WRITE_RESPONSE).finish()),
            #[cfg(feature = "eatt")]
            PREPARE_WRITE_REQUEST => self.prepare_write(params, level, out),
            #[cfg(feature = "eatt")]
            EXECUTE_WRITE_REQUEST => self.execute_write(params, level, app, out),
            #[cfg(feature = "eatt")]
            READ_MULTIPLE_VARIABLE_REQUEST => self.read_multiple(params, level, app, out),
            WRITE_COMMAND => {
                // A command is never answered, not even with an error.
                let _ignored: Result<(), Failure> = self.write(params, level, app, false);
                return None;
            },
            // No indication is sent, so nothing waits for a confirmation.
            CONFIRMATION => return None,
            _ if opcode & COMMAND_FLAG != 0 || NOT_REQUESTS.contains(&opcode) => return None,
            _ => Err((0, AttError::REQUEST_NOT_SUPPORTED)),
        };
        Some(answer.unwrap_or_else(|(handle, error)| error_response(out, opcode, handle, error)))
    }

    /// The server of a new link over the table `db`, with no subscriptions.
    #[inline]
    #[must_use = "the server is only built"]
    pub const fn new(db: &'static Db) -> Self {
        Self {
            #[cfg(feature = "eatt")]
            client_features: 0,
            db,
            #[cfg(feature = "att-mtu")]
            mtu: MTU.saturating_cast(),
            #[cfg(feature = "eatt")]
            prepared: Prepared::new(),
            subscriptions: Subscriptions::new(),
        }
    }

    /// A Handle Value Notification of `data` for `characteristic` on a link
    /// of security `level`, written into `out`; returns its length.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent.
    #[inline]
    pub const fn notify(
        &self,
        characteristic: Char,
        data: &[u8],
        level: Sec,
        out: &mut [u8; MTU],
    ) -> Result<usize, NotifyError> {
        let subscribed = characteristic.cccd().is_some_and(const |index| self.subscriptions.notifying(index));
        check_notify(characteristic, subscribed, data, level)?;
        Ok(handle_value(out, characteristic.handle(), data))
    }

    /// A Multiple Handle Value Notification of `values`, each a
    /// characteristic and its value, on a link of security `level`, written
    /// into `out`; returns its length. Each value is checked as
    /// [`Self::notify`] checks it, and all of them go into the one PDU, never
    /// cut.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent: [`NotifyError::Unsupported`] unless the client
    /// set bit 2 of its Client Supported Features, or for fewer than two
    /// values; [`NotifyError::TooLong`] if they do not fit [`MTU`] octets.
    #[cfg(feature = "eatt")]
    #[inline]
    pub const fn notify_multiple(
        &self,
        values: &[(Char, &[u8])],
        level: Sec,
        out: &mut [u8; MTU],
    ) -> Result<usize, NotifyError> {
        if self.client_features & MULTIPLE_NOTIFICATIONS == 0 || values.len() < 2 {
            return Err(NotifyError::Unsupported);
        }
        let mut writer = Writer::new(out, MULTIPLE_NOTIFICATION);
        let mut rest = values;
        while let Some((&(characteristic, data), tail)) = rest.split_first() {
            let subscribed = characteristic.cccd().is_some_and(const |index| self.subscriptions.notifying(index));
            check_notify(characteristic, subscribed, data, level)?;
            let [handle0, handle1] = characteristic.handle().to_le_bytes();
            let [len0, len1] = data.len().saturating_cast::<u16>().to_le_bytes();
            if !writer.push(&[handle0, handle1, len0, len1]) || !writer.push(data) {
                return Err(NotifyError::TooLong);
            }
            rest = tail;
        }
        Ok(writer.finish())
    }

    /// The characteristic properties of the characteristic that owns the
    /// descriptor at `handle`.
    const fn owner_props(&self, handle: u16) -> u8 {
        let mut previous = handle;
        while previous > 1 {
            previous = previous.saturating_sub(1);
            if let Some(Kind::Characteristic(props)) = self.db.attr(previous).map(Attr::kind) {
                return props;
            }
        }
        0
    }

    /// Answers a Prepare Write Request: queues its part of a value if the
    /// link may write the attribute and the part follows the queued ones, and
    /// echoes the request.
    #[cfg(feature = "eatt")]
    fn prepare_write(&mut self, params: &[u8], level: Sec, out: &mut [u8]) -> Answer {
        // The response repeats the request, which has to fit the ATT MTU.
        let Some((&[handle0, handle1, offset0, offset1], part)) = params.split_first_chunk::<4>() else {
            return Err((0, AttError::INVALID_PDU));
        };
        if params.len() >= out.len() {
            return Err((0, AttError::INVALID_PDU));
        }
        let handle = u16::from_le_bytes([handle0, handle1]);
        let attr = self.db.attr(handle).ok_or((handle, AttError::INVALID_HANDLE))?;
        permit(attr.access().write, level, AttError::WRITE_NOT_PERMITTED).map_err(|error| (handle, error))?;
        if !self.prepared.push(handle, u16::from_le_bytes([offset0, offset1]), part) {
            return Err((handle, AttError::PREPARE_QUEUE_FULL));
        }
        let mut writer = Writer::new(out, PREPARE_WRITE_RESPONSE);
        writer.push(params);
        Ok(writer.finish())
    }

    /// Answers a Read Request.
    fn read(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8]) -> Answer {
        let &[handle0, handle1] = params else { return Err((0, AttError::INVALID_PDU)) };
        self.read_at(u16::from_le_bytes([handle0, handle1]), 0, level, app, out, READ_RESPONSE)
    }

    /// Answers a read of the attribute at `handle` from `offset` with a
    /// response `opcode` in `out`.
    fn read_at(&self, handle: u16, offset: usize, level: Sec, app: &dyn Handler, out: &mut [u8], opcode: u8) -> Answer {
        let attr = self.db.attr(handle).ok_or((handle, AttError::INVALID_HANDLE))?;
        permit(attr.access().read, level, AttError::READ_NOT_PERMITTED).map_err(|error| (handle, error))?;
        let source = self.value(handle, attr, app).map_err(|error| (handle, error))?;
        let mut writer = Writer::new(out, opcode);
        let len = source.copy(offset, writer.rest()).map_err(|error| (handle, error))?;
        writer.len = writer.len.saturating_add(len);
        Ok(writer.finish())
    }

    /// Answers a Read Blob Request.
    fn read_blob(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8]) -> Answer {
        let &[handle0, handle1, offset0, offset1] = params else { return Err((0, AttError::INVALID_PDU)) };
        let handle = u16::from_le_bytes([handle0, handle1]);
        let offset = usize::from(u16::from_le_bytes([offset0, offset1]));
        self.read_at(handle, offset, level, app, out, READ_BLOB_RESPONSE)
    }

    /// Answers a Read By Group Type Request: primary services only.
    fn read_by_group_type(&self, params: &[u8], out: &mut [u8]) -> Answer {
        let (start, end, group) = typed_range(params)?;
        if !Uuid::U16(PRIMARY_SERVICE).matches(group) {
            let error = if Uuid::U16(SECONDARY_SERVICE).matches(group) {
                AttError::ATTRIBUTE_NOT_FOUND
            } else {
                AttError::UNSUPPORTED_GROUP_TYPE
            };
            return Err((start, error));
        }
        let mut writer = Writer::new(out, READ_BY_GROUP_TYPE_RESPONSE);
        let mut size = None;
        for (handle, attr) in self.within(start, end) {
            if attr.kind() != Kind::Service {
                continue;
            }
            let uuid = attr.uuid();
            let entry_len = uuid.wire_len().saturating_add(4);
            if *size.get_or_insert(entry_len) != entry_len {
                break;
            }
            if writer.len == 1 {
                writer.push(&[entry_len.saturating_cast()]);
            }
            let mut entry: [u8; 20] = [0; 20];
            let [handle0, handle1] = handle.to_le_bytes();
            let [group0, group1] = self.db.group_end(handle).to_le_bytes();
            entry[..4].copy_from_slice(&[handle0, handle1, group0, group1]);
            uuid.write(&mut entry[4..]);
            if !writer.push(entry.get(..entry_len).unwrap_or_default()) {
                break;
            }
        }
        writer.found(start)
    }

    /// Answers a Read By Type Request: the values of the attributes of the
    /// type, as long as they have the length of the first and may be read,
    /// each cut to the ATT MTU less 4 octets.
    fn read_by_type(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8]) -> Answer {
        let (start, end, wanted) = typed_range(params)?;
        // The opcode, the entries' length and the handle come before it.
        let value_max = out.len().saturating_sub(4);
        let mut writer = Writer::new(out, READ_BY_TYPE_RESPONSE);
        let mut pair_len = None;
        for (handle, attr) in self.within(start, end) {
            if !attr.type_uuid().matches(wanted) {
                continue;
            }
            let read = permit(attr.access().read, level, AttError::READ_NOT_PERMITTED)
                .and_then(|()| self.value(handle, attr, app));
            let source = match read {
                Ok(source) => source,
                // The first attribute's error is the answer; a later one
                // ends the response before it.
                Err(error) if pair_len.is_none() => return Err((handle, error)),
                Err(_) => break,
            };
            let mut value: [u8; ATT_MAX.strict_sub(4)] = [0; ATT_MAX.strict_sub(4)];
            let len = source.copy(0, value.get_mut(..value_max).unwrap_or_default()).unwrap_or_default();
            let entry_len = len.saturating_add(2);
            if *pair_len.get_or_insert(entry_len) != entry_len {
                break;
            }
            if writer.len == 1 {
                writer.push(&[entry_len.saturating_cast()]);
            }
            if writer.rest().len() < entry_len {
                break;
            }
            writer.push(&handle.to_le_bytes());
            writer.push(value.get(..len).unwrap_or_default());
        }
        writer.found(start)
    }

    /// Answers a Read Multiple Variable Length Request: the length and value
    /// of each attribute, in the order of the request, cut after the ATT MTU
    /// less 1 octets, or before a length field that would not fit whole.
    #[cfg(feature = "eatt")]
    fn read_multiple(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8]) -> Answer {
        let (handles, &[]) = params.as_chunks::<2>() else { return Err((0, AttError::INVALID_PDU)) };
        if handles.len() < 2 {
            return Err((0, AttError::INVALID_PDU));
        }
        // The first handle with the most important error, by its rank.
        let mut failure: Option<(u8, Failure)> = None;
        for &handle_bytes in handles {
            let handle = u16::from_le_bytes(handle_bytes);
            let error = self.db.attr(handle).map_or(Some(AttError::INVALID_HANDLE), |attr| {
                permit(attr.access().read, level, AttError::READ_NOT_PERMITTED).err()
            });
            if let Some(found) = error
                && failure.is_none_or(|(rank, _)| read_rank(found) < rank)
            {
                failure = Some((read_rank(found), (handle, found)));
            }
        }
        if let Some((_, first)) = failure {
            return Err(first);
        }
        let mut writer = Writer::new(out, READ_MULTIPLE_VARIABLE_RESPONSE);
        for &handle_bytes in handles {
            let handle = u16::from_le_bytes(handle_bytes);
            let attr = self.db.attr(handle).ok_or((handle, AttError::INVALID_HANDLE))?;
            let source = self.value(handle, attr, app).map_err(|error| (handle, error))?;
            if !writer.push(&source.len().saturating_cast::<u16>().to_le_bytes()) {
                break;
            }
            let len = source.copy(0, writer.rest()).map_err(|error| (handle, error))?;
            writer.len = writer.len.saturating_add(len);
        }
        Ok(writer.finish())
    }

    /// Takes the client characteristic configuration a bond restores. It
    /// counts as written on no link yet.
    ///
    /// The engine calls it only once the link is encrypted with the bond's
    /// key, never at the connection: a value whose characteristic is open,
    /// such as the battery level, would otherwise be notified before the
    /// encryption, which `BlueZ` does not expect, and would take a link layer
    /// buffer that pairing needs.
    #[inline]
    pub const fn restore(&mut self, subscriptions: Subscriptions) { self.subscriptions = subscriptions; }

    /// Adds the Client Supported Features a bond restores, `bits`, to those
    /// the client wrote on this link: a client never clears a bit, and one
    /// that wrote before the link was encrypted keeps what it wrote.
    #[cfg(feature = "eatt")]
    #[inline]
    pub const fn restore_client_features(&mut self, bits: u8) { self.client_features |= bits & CLIENT_FEATURES; }

    /// The link's client characteristic configuration.
    #[inline]
    #[must_use = "the configuration is only read"]
    pub const fn subscriptions(&self) -> Subscriptions { self.subscriptions }

    /// The value of the attribute `attr` at `handle`, as a read gives it.
    fn value(&self, handle: u16, attr: &Attr, app: &dyn Handler) -> Result<Source, AttError> {
        let mut bytes: [u8; LOCAL_MAX] = [0; LOCAL_MAX];
        let len = match (attr.kind(), attr.value_source()) {
            (Kind::Service, _) => attr.uuid().write(&mut bytes),
            (Kind::Characteristic(props), _) => {
                let [value0, value1] = handle.saturating_add(1).to_le_bytes();
                bytes[..3].copy_from_slice(&[props, value0, value1]);
                attr.uuid().write(&mut bytes[3..]).saturating_add(3)
            },
            (_, Value::Cccd(index)) => {
                bytes[..2].copy_from_slice(&self.subscriptions.value(index).to_le_bytes());
                2
            },
            (_, Value::Const(constant)) => return Ok(Source::Static(constant)),
            (_, Value::Dynamic(id)) => app.read(id, &mut bytes)?.min(LOCAL_MAX),
            (_, Value::Empty | Value::Sink) => 0,
            (_, Value::Hash) => {
                let hash = self.db.hash();
                bytes[..16].copy_from_slice(&hash);
                hash.len()
            },
            #[cfg(feature = "eatt")]
            (_, Value::ClientFeatures) => {
                bytes[0] = self.client_features;
                1
            },
            #[cfg(feature = "eatt")]
            (_, Value::ServerFeatures) => {
                bytes[0] = SERVER_FEATURES;
                1
            },
            (_, Value::Zeros(len)) => return Ok(Source::Zeros(usize::from(len))),
        };
        Ok(Source::Local { bytes, len })
    }

    /// The attributes from `start` to `end`, as far as the table goes.
    fn within(&self, start: u16, end: u16) -> impl Iterator<Item = (u16, &'static Attr)> {
        let db = self.db;
        (start..=end.min(db.last_handle())).filter_map(move |handle| db.attr(handle).map(|attr| (handle, attr)))
    }

    /// Takes a Write Request (`with_response`) or a Write Command.
    fn write(&mut self, params: &[u8], level: Sec, app: &dyn Handler, with_response: bool) -> Result<(), Failure> {
        let Some((&[handle0, handle1], data)) = params.split_first_chunk::<2>() else {
            return Err((0, AttError::INVALID_PDU));
        };
        self.write_value(u16::from_le_bytes([handle0, handle1]), data, level, app, with_response)
    }

    /// Writes `data` to the attribute at `handle`, for a Write Request
    /// (`with_response`), a Write Command or an Execute Write Request.
    fn write_value(
        &mut self,
        handle: u16,
        data: &[u8],
        level: Sec,
        app: &dyn Handler,
        with_response: bool,
    ) -> Result<(), Failure> {
        let attr = self.db.attr(handle).ok_or((handle, AttError::INVALID_HANDLE))?;
        permit(attr.access().write, level, AttError::WRITE_NOT_PERMITTED).map_err(|error| (handle, error))?;
        match attr.value_source() {
            Value::Cccd(index) => {
                let &[value0, value1] = data else { return Err((handle, AttError::INVALID_ATTRIBUTE_VALUE_LENGTH)) };
                let props = self.owner_props(handle);
                self.subscriptions.set(index, u16::from_le_bytes([value0, value1]), props);
                Ok(())
            },
            Value::Dynamic(id) => app.write(id, data, with_response).map_err(|error| (handle, error)),
            Value::Sink => Ok(()),
            #[cfg(feature = "eatt")]
            Value::ClientFeatures => {
                // An empty write is 0; a client never clears a bit it set.
                let bits = data.first().copied().unwrap_or(0) & CLIENT_FEATURES;
                if self.client_features & !bits != 0 {
                    return Err((handle, AttError::VALUE_NOT_ALLOWED));
                }
                self.client_features = bits;
                Ok(())
            },
            #[cfg(feature = "eatt")]
            Value::ServerFeatures => Err((handle, AttError::WRITE_NOT_PERMITTED)),
            Value::Const(_) | Value::Empty | Value::Hash | Value::Zeros(_) => {
                Err((handle, AttError::WRITE_NOT_PERMITTED))
            },
        }
    }
}

#[cfg(feature = "eatt")]
impl Prepared {
    /// An empty queue.
    const fn new() -> Self { Self { bytes: [0; PREPARE_MAX], handle: 0, len: 0, offset: 0 } }

    /// Queues `part` of the value of the attribute at `handle`, from
    /// `offset` in it: the first part, or one that follows the last part of
    /// the same attribute, as long as the queue holds it all. Returns
    /// whether it was queued; a part that was not changes nothing.
    const fn push(&mut self, handle: u16, offset: u16, part: &[u8]) -> bool {
        let (start, queued) = if self.handle == 0 { (offset, 0) } else { (self.offset, usize::from(self.len)) };
        let follows = self.handle == 0
            || (handle == self.handle && usize::from(offset) == usize::from(self.offset).saturating_add(queued));
        let total = queued.saturating_add(part.len());
        let Some(target) = self.bytes.get_mut(queued..total) else { return false };
        if !follows {
            return false;
        }
        target.copy_from_slice(part);
        self.handle = handle;
        self.offset = start;
        self.len = total.saturating_cast();
        true
    }

    /// The queued octets.
    const fn value(&self) -> &[u8] { self.bytes.get(..usize::from(self.len)).unwrap_or_default() }
}

impl Source {
    /// Copies the value from `offset` into `out`, as much as fits, and
    /// returns the number of octets copied.
    fn copy(self, offset: usize, out: &mut [u8]) -> Result<usize, AttError> {
        let local;
        let bytes: &[u8] = match self {
            Self::Local { bytes, len } => {
                local = bytes;
                local.get(..len).unwrap_or_default()
            },
            Self::Static(bytes) => bytes,
            Self::Zeros(len) => {
                let count = len.checked_sub(offset).ok_or(AttError::INVALID_OFFSET)?.min(out.len());
                out.get_mut(..count).unwrap_or_default().fill(0);
                return Ok(count);
            },
        };
        let source = bytes.get(offset..).ok_or(AttError::INVALID_OFFSET)?;
        let count = source.len().min(out.len());
        out.get_mut(..count).unwrap_or_default().copy_from_slice(source.get(..count).unwrap_or_default());
        Ok(count)
    }

    /// The length of the whole value.
    #[cfg(feature = "eatt")]
    const fn len(&self) -> usize {
        match *self {
            Self::Local { bytes: _, len } | Self::Zeros(len) => len,
            Self::Static(bytes) => bytes.len(),
        }
    }
}

impl<'out> Writer<'out> {
    /// The response's length.
    const fn finish(self) -> usize { self.len }

    /// The response's length if it holds an entry, otherwise Attribute Not
    /// Found for the range starting at `start`.
    const fn found(self, start: u16) -> Answer {
        if self.len > 2 { Ok(self.len) } else { Err((start, AttError::ATTRIBUTE_NOT_FOUND)) }
    }

    /// A response with `opcode` in `buf`; an empty `buf` holds nothing, not
    /// even the opcode.
    const fn new(buf: &'out mut [u8], opcode: u8) -> Self {
        let Some(first) = buf.first_mut() else { return Self { buf, len: 0 } };
        *first = opcode;
        Self { buf, len: 1 }
    }

    /// Appends `bytes` if they fit; returns whether they did.
    const fn push(&mut self, bytes: &[u8]) -> bool {
        let Some(rest) = self.buf.get_mut(self.len..) else { return false };
        let Some(target) = rest.get_mut(..bytes.len()) else { return false };
        target.copy_from_slice(bytes);
        self.len = self.len.saturating_add(bytes.len());
        true
    }

    /// The room left.
    const fn rest(&mut self) -> &mut [u8] { self.buf.get_mut(self.len..).unwrap_or_default() }
}

/// Checks a notification of `data` for `characteristic`, `subscribed` or
/// not, on a link of security `level`.
const fn check_notify(characteristic: Char, subscribed: bool, data: &[u8], level: Sec) -> Result<(), NotifyError> {
    if characteristic.props() & PROP_NOTIFY == 0 || !subscribed {
        return Err(NotifyError::NotSubscribed);
    }
    if !characteristic.sec().met_by(level) {
        return Err(NotifyError::Insecure);
    }
    if data.len() > NOTIFY_MAX {
        return Err(NotifyError::TooLong);
    }
    Ok(())
}

/// Writes an Error Response to the request `opcode` for `handle` with
/// `error` into `out` and returns its length.
const fn error_response(out: &mut [u8], opcode: u8, handle: u16, error: AttError) -> usize {
    let [handle0, handle1] = handle.to_le_bytes();
    let mut writer = Writer::new(out, ERROR_RESPONSE);
    writer.push(&[opcode, handle0, handle1, error.code()]);
    writer.finish()
}

/// Writes a Handle Value Notification of `data` for `handle` into `out` and
/// returns its length.
const fn handle_value(out: &mut [u8], handle: u16, data: &[u8]) -> usize {
    let mut writer = Writer::new(out, NOTIFICATION);
    writer.push(&handle.to_le_bytes());
    writer.push(data);
    writer.finish()
}

/// Checks that a link of security `level` meets the requirement
/// `required`; `denied` if nobody may.
const fn permit(required: Option<Sec>, level: Sec, denied: AttError) -> Result<(), AttError> {
    match required {
        None => Err(denied),
        Some(sec) if sec.met_by(level) => Ok(()),
        Some(Sec::Authenticated) => Err(AttError::INSUFFICIENT_AUTHENTICATION),
        Some(_) => Err(AttError::INSUFFICIENT_ENCRYPTION),
    }
}

/// The rank of an error of a Read Multiple Variable Length Request, the most
/// important lowest: the specification's order of authentication,
/// encryption, the handle and the permission, which every server error
/// before the read of the value is.
#[cfg(feature = "eatt")]
const fn read_rank(error: AttError) -> u8 {
    match error {
        AttError::INSUFFICIENT_AUTHENTICATION => 0,
        AttError::INSUFFICIENT_ENCRYPTION => 1,
        AttError::INVALID_HANDLE => 2,
        _ => 3,
    }
}

/// The handle range of a request: Invalid Handle for a start of 0 or after
/// the end.
const fn range(start_bytes: [u8; 2], end_bytes: [u8; 2]) -> Result<(u16, u16), Failure> {
    let (start, end) = (u16::from_le_bytes(start_bytes), u16::from_le_bytes(end_bytes));
    if start == 0 || start > end {
        return Err((start, AttError::INVALID_HANDLE));
    }
    Ok((start, end))
}

/// The handle range and the attribute type of a Read By Type or Read By
/// Group Type Request, whose type is a 16-bit or a 128-bit UUID.
const fn typed_range(params: &[u8]) -> Result<(u16, u16, &[u8]), Failure> {
    let Some((&[start0, start1, end0, end1], uuid)) = params.split_first_chunk::<4>() else {
        return Err((0, AttError::INVALID_PDU));
    };
    if uuid.len() != 2 && uuid.len() != 16 {
        return Err((0, AttError::INVALID_PDU));
    }
    let (start, end) = range([start0, start1], [end0, end1])?;
    Ok((start, end, uuid))
}

#[cfg(test)] mod tests;
