//! The attribute protocol, as a server with the default MTU of 23 octets.
//!
//! [`Server`] decodes the requests BlueZ sends, answers them from the GATT
//! table ([`crate::host::gatt::Db`]) with the error codes of the Core
//! specification, and encodes notifications and indications. One request is
//! outstanding at a time, so the engine keeps one response slot of
//! [`MTU`] octets. One indication waits for its confirmation; the 30 s limit
//! on that wait is for the engine to time, which does not send indications
//! yet.
//!
//! It serves exactly these requests:
//!
//! - Exchange MTU: the answer is always 23.
//! - Find Information.
//! - Find By Type Value, for primary services (0x2800) only.
//! - Read By Type, for any attribute type: characteristic declarations (0x2803)
//!   are grouped by the size of their UUID, so one response holds entries of
//!   length 7 or 21 only. Includes (0x2802) and Server Supported Features
//!   (0x2B3A) are not in the table and give Attribute Not Found (0x0A); the
//!   Database Hash (0x2B2A) gives the table's hash.
//! - Read, and Read Blob: an offset equal to the value's length gives an empty
//!   response, a larger one Invalid Offset (0x07), never Attribute Not Long
//!   (0x0B), which would fail BlueZ's whole read.
//! - Read By Group Type for primary services, with the real end handle of the
//!   last service; secondary services (0x2801) give 0x0A, any other type
//!   Unsupported Group Type (0x10).
//! - Write Request and Write Command; Handle Value Confirmation.
//!
//! Any other request gets Request Not Supported (0x06); a command (opcode bit
//! 6) is never answered, not even when it fails, and an unexpected response
//! is ignored, as BlueZ shuts the bearer down on an unsolicited one. A request
//! with the wrong length gets Invalid PDU (0x04), and a client characteristic
//! configuration write of a length other than 2 Invalid Attribute Value
//! Length (0x0D). Other configuration writes are taken leniently: only the
//! bits the characteristic's properties allow are kept.
//!
//! An attribute that needs encryption is served only for a request that was
//! itself received encrypted ([`crate::link::AclIn::encrypted`]) on a link
//! whose key the host handed to the link layer itself, with
//! [`crate::link::Link::ltk_reply`]; the engine gives that as the security
//! of each request, so the check never depends on the order in which the
//! host learns of the encryption. A request that lacks it gets Insufficient
//! Encryption (0x0F), never Insufficient Authentication (0x05), on which
//! BlueZ would ask for pairing with protection against a man in the middle,
//! and Just Works pairing would fail. The table refuses attributes that
//! need authenticated pairing while it is compiled
//! ([`crate::host::gatt::Db::new`]), so the server never sends 0x05.
//!
//! Notifications and indications need the security their characteristic
//! was declared with, also for a characteristic that can be neither read
//! nor written.

use crate::host::gatt::{
    AttError,
    Attr,
    Char,
    DYNAMIC_MAX,
    Db,
    Handler,
    Kind,
    PRIMARY_SERVICE,
    PROP_INDICATE,
    PROP_NOTIFY,
    SECONDARY_SERVICE,
    Sec,
    Subscriptions,
    Uuid,
    Value,
};

/// The ATT MTU: the default, which the server never raises.
pub const MTU: usize = 23;
/// Longest value a notification or indication carries.
pub const NOTIFY_MAX: usize = MTU - 3;
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
/// The range a Service Changed indication names: the whole table.
const WHOLE_RANGE: [u8; 4] = [0x01, 0x00, 0xFF, 0xFF];
/// Longest value the server builds itself: a characteristic declaration
/// with a 128-bit UUID is 19 octets, a dynamic value up to 22.
const LOCAL_MAX: usize = DYNAMIC_MAX;

/// Why a notification or an indication cannot be sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum NotifyError {
    /// The link lacks the security the characteristic needs.
    Insecure,
    /// The client has not enabled it, or the characteristic cannot do it.
    NotSubscribed,
    /// An indication still waits for its confirmation.
    Pending,
    /// The value is longer than [`NOTIFY_MAX`].
    TooLong,
}

/// The attribute server of one link: the table, the link's client
/// characteristic configuration and the indication waiting for its
/// confirmation.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Server {
    /// The table.
    db:            &'static Db,
    /// Whether an indication waits for its confirmation.
    indicating:    bool,
    /// The link's client characteristic configuration.
    subscriptions: Subscriptions,
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
    /// The response slot.
    buf: &'out mut [u8; MTU],
    /// Octets written.
    len: usize,
}

impl Server {
    /// Forgets the indication waiting for its confirmation, after its 30 s
    /// timeout ended the link.
    #[inline]
    pub const fn cancel_indication(&mut self) { self.indicating = false; }

    /// Answers an Exchange MTU Request: always the default MTU.
    fn exchange_mtu(params: &[u8], out: &mut [u8; MTU]) -> Answer {
        if params.len() != 2 {
            return Err((0, AttError::INVALID_PDU));
        }
        let [low, high] = u16::try_from(MTU).unwrap_or_default().to_le_bytes();
        let mut writer = Writer::new(out, EXCHANGE_MTU_RESPONSE);
        writer.push(&[low, high]);
        Ok(writer.finish())
    }

    /// Answers a Find By Type Value Request: primary services with the
    /// given UUID, with their end handles.
    fn find_by_type_value(&self, params: &[u8], out: &mut [u8; MTU]) -> Answer {
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
    fn find_information(&self, params: &[u8], out: &mut [u8; MTU]) -> Answer {
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
            let mut entry = [0_u8; 18];
            let [handle0, handle1] = handle.to_le_bytes();
            entry[0] = handle0;
            entry[1] = handle1;
            let len = entry.get_mut(2..).map_or(0, |rest| uuid.write(rest)).saturating_add(2);
            if !writer.push(entry.get(..len).unwrap_or_default()) {
                break;
            }
        }
        writer.found(start)
    }

    /// Answers a request, `pdu`, whose security is `level`: open unless it
    /// was received encrypted on a link whose key the host handed to the
    /// link layer itself. Writes the response into `out` and returns its
    /// length, `None` for a PDU that gets no response: a command, a
    /// confirmation or a response.
    #[inline]
    pub fn handle(&mut self, pdu: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8; MTU]) -> Option<usize> {
        let (&opcode, params) = pdu.split_first()?;
        let answer = match opcode {
            EXCHANGE_MTU_REQUEST => Self::exchange_mtu(params, out),
            FIND_INFORMATION_REQUEST => self.find_information(params, out),
            FIND_BY_TYPE_VALUE_REQUEST => self.find_by_type_value(params, out),
            READ_BY_TYPE_REQUEST => self.read_by_type(params, level, app, out),
            READ_REQUEST => self.read(params, level, app, out),
            READ_BLOB_REQUEST => self.read_blob(params, level, app, out),
            READ_BY_GROUP_TYPE_REQUEST => self.read_by_group_type(params, out),
            WRITE_REQUEST => self.write(params, level, app, true).map(|()| Writer::new(out, WRITE_RESPONSE).finish()),
            WRITE_COMMAND => {
                // A command is never answered, not even with an error.
                let _ignored: Result<(), Failure> = self.write(params, level, app, false);
                return None;
            },
            CONFIRMATION => {
                if params.is_empty() {
                    self.indicating = false;
                }
                return None;
            },
            _ if opcode & COMMAND_FLAG != 0 || NOT_REQUESTS.contains(&opcode) => return None,
            _ => Err((0, AttError::REQUEST_NOT_SUPPORTED)),
        };
        Some(answer.unwrap_or_else(|(handle, error)| error_response(out, opcode, handle, error)))
    }

    /// A Handle Value Indication of `data` for `characteristic` on a link of
    /// security `level`, written into `out`; returns its length. The
    /// indication then waits for its confirmation.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent: [`NotifyError::Pending`] while the previous
    /// one waits for its confirmation.
    #[inline]
    pub fn indicate(
        &mut self,
        characteristic: Char,
        data: &[u8],
        level: Sec,
        out: &mut [u8; MTU],
    ) -> Result<usize, NotifyError> {
        let subscribed = characteristic.cccd().is_some_and(|index| self.subscriptions.indicating(index));
        check_notify(characteristic, PROP_INDICATE, subscribed, data, level)?;
        if self.indicating {
            return Err(NotifyError::Pending);
        }
        self.indicating = true;
        Ok(handle_value(out, INDICATION, characteristic.handle(), data))
    }

    /// Whether an indication waits for its confirmation.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn is_indicating(&self) -> bool { self.indicating }

    /// The server of a new link over the table `db`, with no subscriptions.
    #[inline]
    #[must_use = "the server is only built"]
    pub const fn new(db: &'static Db) -> Self { Self { db, indicating: false, subscriptions: Subscriptions::new() } }

    /// A Handle Value Notification of `data` for `characteristic` on a link
    /// of security `level`, written into `out`; returns its length.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent.
    #[inline]
    pub fn notify(
        &self,
        characteristic: Char,
        data: &[u8],
        level: Sec,
        out: &mut [u8; MTU],
    ) -> Result<usize, NotifyError> {
        let subscribed = characteristic.cccd().is_some_and(|index| self.subscriptions.notifying(index));
        check_notify(characteristic, PROP_NOTIFY, subscribed, data, level)?;
        Ok(handle_value(out, NOTIFICATION, characteristic.handle(), data))
    }

    /// The characteristic properties of the characteristic that owns the
    /// descriptor at `handle`.
    fn owner_props(&self, handle: u16) -> u8 {
        let mut previous = handle;
        while previous > 1 {
            previous = previous.saturating_sub(1);
            if let Some(Kind::Characteristic(props)) = self.db.attr(previous).map(Attr::kind) {
                return props;
            }
        }
        0
    }

    /// Answers a Read Request.
    fn read(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8; MTU]) -> Answer {
        let &[handle0, handle1] = params else { return Err((0, AttError::INVALID_PDU)) };
        self.read_at(u16::from_le_bytes([handle0, handle1]), 0, level, app, Writer::new(out, READ_RESPONSE))
    }

    /// Answers a read of the attribute at `handle` from `offset` with the
    /// response `writer` started.
    fn read_at(&self, handle: u16, offset: usize, level: Sec, app: &dyn Handler, mut writer: Writer<'_>) -> Answer {
        let attr = self.db.attr(handle).ok_or((handle, AttError::INVALID_HANDLE))?;
        permit(attr.access().read, level, AttError::READ_NOT_PERMITTED).map_err(|error| (handle, error))?;
        let source = self.value(handle, attr, app).map_err(|error| (handle, error))?;
        let len = source.copy(offset, writer.rest()).map_err(|error| (handle, error))?;
        writer.len = writer.len.saturating_add(len);
        Ok(writer.finish())
    }

    /// Answers a Read Blob Request.
    fn read_blob(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8; MTU]) -> Answer {
        let &[handle0, handle1, offset0, offset1] = params else { return Err((0, AttError::INVALID_PDU)) };
        let handle = u16::from_le_bytes([handle0, handle1]);
        let offset = usize::from(u16::from_le_bytes([offset0, offset1]));
        self.read_at(handle, offset, level, app, Writer::new(out, READ_BLOB_RESPONSE))
    }

    /// Answers a Read By Group Type Request: primary services only.
    fn read_by_group_type(&self, params: &[u8], out: &mut [u8; MTU]) -> Answer {
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
                writer.push(&[u8::try_from(entry_len).unwrap_or_default()]);
            }
            let mut entry = [0_u8; 20];
            let [handle0, handle1] = handle.to_le_bytes();
            let [group0, group1] = self.db.group_end(handle).to_le_bytes();
            if let Some(header) = entry.first_chunk_mut::<4>() {
                *header = [handle0, handle1, group0, group1];
            }
            entry.get_mut(4..).map(|rest| uuid.write(rest));
            if !writer.push(entry.get(..entry_len).unwrap_or_default()) {
                break;
            }
        }
        writer.found(start)
    }

    /// Answers a Read By Type Request: the values of the attributes of the
    /// type, as long as they have the length of the first and may be read.
    fn read_by_type(&self, params: &[u8], level: Sec, app: &dyn Handler, out: &mut [u8; MTU]) -> Answer {
        let (start, end, wanted) = typed_range(params)?;
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
            let mut value = [0_u8; MTU - 4];
            let len = source.copy(0, &mut value).unwrap_or_default();
            let entry_len = len.saturating_add(2);
            if *pair_len.get_or_insert(entry_len) != entry_len {
                break;
            }
            if writer.len == 1 {
                writer.push(&[u8::try_from(entry_len).unwrap_or_default()]);
            }
            if writer.rest().len() < entry_len {
                break;
            }
            writer.push(&handle.to_le_bytes());
            writer.push(value.get(..len).unwrap_or_default());
        }
        writer.found(start)
    }

    /// Takes the client characteristic configuration a bond restores. It
    /// counts as written on no link yet.
    ///
    /// The engine calls it only once the link is encrypted with the bond's
    /// key, never at the connection: a value whose characteristic is open,
    /// such as the battery level, would otherwise be notified before the
    /// encryption, which BlueZ does not expect, and would take a link layer
    /// buffer that pairing needs.
    #[inline]
    pub const fn restore(&mut self, subscriptions: Subscriptions) { self.subscriptions = subscriptions; }

    /// A Service Changed indication of the whole table, written into `out`,
    /// if the table has the characteristic and the client wrote its
    /// configuration on this link with indications on, and no indication
    /// waits. It is to be asked for only after the Write Response to that
    /// write went out, as BlueZ registers its handler only then; an earlier
    /// indication would be confirmed and dropped. The engine does not ask
    /// for it yet: that ordering is still to be done, with the 30 s timer
    /// of the confirmation.
    #[inline]
    pub fn service_changed(&mut self, level: Sec, out: &mut [u8; MTU]) -> Option<usize> {
        let characteristic = self.db.service_changed()?;
        if !self.subscriptions.is_written(characteristic.cccd()?) {
            return None;
        }
        self.indicate(characteristic, &WHOLE_RANGE, level, out).ok()
    }

    /// The link's client characteristic configuration.
    #[inline]
    #[must_use = "the configuration is only read"]
    pub const fn subscriptions(&self) -> Subscriptions { self.subscriptions }

    /// The value of the attribute `attr` at `handle`, as a read gives it.
    fn value(&self, handle: u16, attr: &Attr, app: &dyn Handler) -> Result<Source, AttError> {
        let mut bytes = [0_u8; LOCAL_MAX];
        let len = match (attr.kind(), attr.value_source()) {
            (Kind::Service, _) => attr.uuid().write(&mut bytes),
            (Kind::Characteristic(props), _) => {
                let [value0, value1] = handle.saturating_add(1).to_le_bytes();
                if let Some(header) = bytes.first_chunk_mut::<3>() {
                    *header = [props, value0, value1];
                }
                bytes.get_mut(3..).map_or(0, |rest| attr.uuid().write(rest)).saturating_add(3)
            },
            (_, Value::Cccd(index)) => {
                if let Some(target) = bytes.first_chunk_mut::<2>() {
                    *target = self.subscriptions.value(index).to_le_bytes();
                }
                2
            },
            (_, Value::Const(constant)) => return Ok(Source::Static(constant)),
            (_, Value::Dynamic(id)) => app.read(id, &mut bytes)?.min(LOCAL_MAX),
            (_, Value::Empty | Value::Sink) => 0,
            (_, Value::Hash) => {
                let hash = self.db.hash();
                bytes.first_chunk_mut::<16>().map_or(0, |target| {
                    *target = hash;
                    hash.len()
                })
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
        let handle = u16::from_le_bytes([handle0, handle1]);
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
            Value::Const(_) | Value::Empty | Value::Hash | Value::Zeros(_) => {
                Err((handle, AttError::WRITE_NOT_PERMITTED))
            },
        }
    }
}

impl Source {
    /// Copies the value from `offset` into `out`, as much as fits, and
    /// returns the number of octets copied.
    fn copy(self, offset: usize, out: &mut [u8]) -> Result<usize, AttError> {
        let local;
        let (bytes, len): (&[u8], usize) = match self {
            Self::Local { bytes, len } => {
                local = bytes;
                (local.get(..len).unwrap_or_default(), len)
            },
            Self::Static(bytes) => (bytes, bytes.len()),
            Self::Zeros(len) => (&[], len),
        };
        let left = len.checked_sub(offset).ok_or(AttError::INVALID_OFFSET)?;
        let count = left.min(out.len());
        for (index, slot) in out.iter_mut().take(count).enumerate() {
            *slot = bytes.get(offset.saturating_add(index)).copied().unwrap_or_default();
        }
        Ok(count)
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

    /// A response with `opcode` in `buf`.
    const fn new(buf: &'out mut [u8; MTU], opcode: u8) -> Self {
        buf[0] = opcode;
        Self { buf, len: 1 }
    }

    /// Appends `bytes` if they fit; returns whether they did.
    fn push(&mut self, bytes: &[u8]) -> bool {
        let end = self.len.saturating_add(bytes.len());
        let Some(target) = self.buf.get_mut(self.len..end) else { return false };
        target.copy_from_slice(bytes);
        self.len = end;
        true
    }

    /// The room left.
    fn rest(&mut self) -> &mut [u8] { self.buf.get_mut(self.len..).unwrap_or_default() }
}

/// Checks a notification or indication (`prop`) of `data` for
/// `characteristic` on a link of security `level`.
const fn check_notify(
    characteristic: Char,
    prop: u8,
    subscribed: bool,
    data: &[u8],
    level: Sec,
) -> Result<(), NotifyError> {
    if characteristic.props() & prop == 0 || !subscribed {
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
fn error_response(out: &mut [u8; MTU], opcode: u8, handle: u16, error: AttError) -> usize {
    let [handle0, handle1] = handle.to_le_bytes();
    let mut writer = Writer::new(out, ERROR_RESPONSE);
    writer.push(&[opcode, handle0, handle1, error.code()]);
    writer.finish()
}

/// Writes a notification or indication (`opcode`) of `data` for `handle`
/// into `out` and returns its length.
fn handle_value(out: &mut [u8; MTU], opcode: u8, handle: u16, data: &[u8]) -> usize {
    let mut writer = Writer::new(out, opcode);
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
fn typed_range(params: &[u8]) -> Result<(u16, u16, &[u8]), Failure> {
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
