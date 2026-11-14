//! The GATT server's attribute table.
//!
//! The table is a constant array in flash, built at compile time by the
//! [`gatt!`](crate::gatt) macro, and the handle of each attribute is one more
//! than its index. A [`Db`] wraps it with what the server needs to know about
//! the whole table: its layout hash ([`hash`]), the number of client
//! characteristic configuration descriptors and the Service Changed
//! characteristic, if the table has one. The ATT server in
//! [`crate::host::att`] answers requests from it.
//!
//! Values are constant bytes ([`Value::Const`]), zeros of a given length
//! ([`Value::Zeros`]), a write sink ([`Value::Sink`]), dynamic values the
//! application reads and writes through [`Handler`] ([`Value::Dynamic`]),
//! client characteristic configuration bits ([`Value::Cccd`]), which the host
//! keeps for each link in [`Subscriptions`] and restores from the bond, or the
//! table's own hash ([`Value::Hash`]).
//!
//! The Service Changed characteristic (0x2A05) is optional, and a table that
//! never changes its layout needs none. Where it is present, the server builds
//! its indication only once that link has written its client characteristic
//! configuration, as `BlueZ` registers its handler only then. The engine does
//! not send indications yet: asking for this one only after the Write Response
//! went out, and timing its confirmation, are still to be done for a table that
//! has the characteristic.
//!
//! Read By Group Type reports the real end handle of the last service, never
//! 0xFFFF: `BlueZ` keeps a cached service whose start handle, UUID and number
//! of handles are unchanged, so the number of handles has to follow the table.
//!
//! The Peripheral Preferred Connection Parameters take their bytes from a
//! [`ParamRange`] with [`ppcp`], the same constant the host's connection
//! parameter request sends
//! ([`crate::host::signal::Signalling::request_params`]), so `BlueZ` never
//! finds the two disagreeing.
//!
//! # The table macro
//!
//! ```
//! use nrf_ble::host::gatt::{Uuid, Value, ValueId};
//!
//! /// The battery level, read through the handler.
//! const LEVEL: ValueId = ValueId::new(0);
//!
//! nrf_ble::gatt! {
//!     /// The table.
//!     pub const DB;
//!     service 0x1800 {
//!         char 0x2A00 [read] = Value::Const(b"Example");
//!     }
//!     service 0x180F {
//!         /// The battery level characteristic.
//!         char BATTERY: 0x2A19 [read, notify] = Value::Dynamic(LEVEL);
//!         ccc;
//!     }
//!     service 0x1812 {
//!         char REPORT: 0x2A4D [read, notify; encrypted] = Value::Zeros(8);
//!         ccc;
//!         desc 0x2908 [read] = Value::Const(&[1, 1]);
//!     }
//! }
//!
//! assert_eq!(BATTERY.handle(), 6);
//! assert_eq!(REPORT.cccd(), Some(1));
//! assert_eq!(DB.last_handle(), 12);
//! # let _ = Uuid::U16(0x2A00);
//! ```
//!
//! Each `service` is a primary service. Each `char` adds the characteristic
//! declaration and its value, with the properties in brackets (`read`,
//! `write`, `write_without_response`, `notify`, `indicate`) and after a
//! semicolon the security its value needs (`encrypted`, or none for an open
//! value); its notifications and indications need it too. A name before the
//! UUID defines a [`Char`] constant of that name. `ccc;` adds the client
//! characteristic configuration descriptor of the characteristic before it,
//! with that characteristic's security, and `desc` adds another descriptor
//! with its permissions (`read`, `write`) and security. A UUID is a 16-bit
//! literal or, in parentheses, an expression of type [`Uuid`]. The table is
//! checked while it is compiled: every characteristic that notifies or
//! indicates has exactly one client characteristic configuration descriptor
//! and no other has one. A table without it does not build:
//!
//! ```compile_fail
//! use nrf_ble::host::gatt::Value;
//!
//! nrf_ble::gatt! {
//!     const DB;
//!     service 0x180F {
//!         char 0x2A19 [read, notify] = Value::Const(&[50]);
//!     }
//! }
//!
//! const CCCDS: u8 = DB.cccds();
//! ```
//!
//! Nor does a host whose table has an attribute that needs authentication
//! (`authenticated`) unless it pairs with Passkey Entry: without the feature
//! `passkey` the table itself is refused, as no link ever has it, and `BlueZ`,
//! answered Insufficient Authentication, would pair again with protection
//! against a man in the middle required, which fails (see [`Db::new`]); with
//! it, a host whose configuration pairs with Just Works only is refused
//! (`Host::new`):
//!
//! ```compile_fail
//! use nrf_ble::{
//!     host::{
//!         Host,
//!         engine::{Config, Unclaimed},
//!         gatt::Value,
//!     },
//!     link::{Link, Shared},
//! };
//!
//! nrf_ble::gatt! {
//!     const DB;
//!     service 0x180F {
//!         char 0x2A19 [read; authenticated] = Value::Const(&[50]);
//!     }
//! }
//!
//! static SHARED: Shared = Shared::new();
//! static HOST: Host<Link<'static>> =
//!     Host::new(Link::new(&SHARED), &DB, Config::new(None, Unclaimed::Keep));
//! ```

/// The constant hash of the table's layout.
pub mod hash;

use crate::link::ParamRange;

/// Builds an attribute table at compile time; see the [module
/// documentation](crate::host::gatt) for the syntax.
#[macro_export]
macro_rules! gatt {
    (@munch $head:tt [$($attrs:tt)*] [$($items:tt)*] ($handle:expr) ($ccc:expr) ($sec:expr)
        service $uuid:tt { $($body:tt)* } $($rest:tt)*
    ) => {
        $crate::gatt!(@munch $head
            [$($attrs)* $crate::host::gatt::Attr::service($crate::gatt!(@uuid $uuid)),]
            [$($items)*] ($handle + 1) ($ccc) ($crate::host::gatt::Sec::Open)
            $($body)* $($rest)*);
    };
    (@munch {[$($db_meta:tt)*] $vis:vis $db:ident} [$($attrs:tt)*] [$($items:tt)*] ($handle:expr) ($ccc:expr)
        ($sec:expr) $(#[$meta:meta])* char $name:ident : $uuid:tt [$($prop:ident),+ $(; $level:ident)?] = $value:expr;
        $($rest:tt)*
    ) => {
        $crate::gatt!(@munch {[$($db_meta)*] $vis $db}
            [$($attrs)*
                $crate::host::gatt::Attr::characteristic($crate::gatt!(@uuid $uuid), 0 $(| $crate::gatt!(@prop $prop))+),
                $crate::host::gatt::Attr::value(
                    $crate::gatt!(@uuid $uuid),
                    0 $(| $crate::gatt!(@prop $prop))+,
                    $crate::gatt!(@sec $($level)?),
                    $value,
                ),
            ]
            [$($items)* $(#[$meta])* $vis const $name: $crate::host::gatt::Char = $db.characteristic($handle);]
            ($handle + 2) ($ccc) ($crate::gatt!(@sec $($level)?))
            $($rest)*);
    };
    (@munch $head:tt [$($attrs:tt)*] [$($items:tt)*] ($handle:expr) ($ccc:expr) ($sec:expr)
        $(#[$meta:meta])* char $uuid:tt [$($prop:ident),+ $(; $level:ident)?] = $value:expr;
        $($rest:tt)*
    ) => {
        $crate::gatt!(@munch $head
            [$($attrs)*
                $crate::host::gatt::Attr::characteristic($crate::gatt!(@uuid $uuid), 0 $(| $crate::gatt!(@prop $prop))+),
                $crate::host::gatt::Attr::value(
                    $crate::gatt!(@uuid $uuid),
                    0 $(| $crate::gatt!(@prop $prop))+,
                    $crate::gatt!(@sec $($level)?),
                    $value,
                ),
            ]
            [$($items)*] ($handle + 2) ($ccc) ($crate::gatt!(@sec $($level)?))
            $($rest)*);
    };
    (@munch $head:tt [$($attrs:tt)*] [$($items:tt)*] ($handle:expr) ($ccc:expr) ($sec:expr)
        ccc; $($rest:tt)*
    ) => {
        $crate::gatt!(@munch $head
            [$($attrs)* $crate::host::gatt::Attr::cccd($sec, $ccc),]
            [$($items)*] ($handle + 1) ($ccc + 1) ($sec)
            $($rest)*);
    };
    (@munch $head:tt [$($attrs:tt)*] [$($items:tt)*] ($handle:expr) ($ccc:expr) ($sec:expr)
        desc $uuid:tt [$($perm:ident),+ $(; $level:ident)?] = $value:expr; $($rest:tt)*
    ) => {
        $crate::gatt!(@munch $head
            [$($attrs)*
                $crate::host::gatt::Attr::descriptor(
                    $crate::gatt!(@uuid $uuid),
                    0 $(| $crate::gatt!(@prop $perm))+,
                    $crate::gatt!(@sec $($level)?),
                    $value,
                ),
            ]
            [$($items)*] ($handle + 1) ($ccc) ($sec)
            $($rest)*);
    };
    (@munch {[$(#[$meta:meta])*] $vis:vis $db:ident} [$($attrs:tt)*] [$($items:tt)*] ($handle:expr) ($ccc:expr)
        ($sec:expr)
    ) => {
        $(#[$meta])*
        $vis const $db: $crate::host::gatt::Db = $crate::host::gatt::Db::new(&[$($attrs)*]);
        $($items)*
    };
    (@uuid ($uuid:expr)) => { $uuid };
    (@uuid $uuid:literal) => { $crate::host::gatt::Uuid::U16($uuid) };
    (@prop read) => { $crate::host::gatt::PROP_READ };
    (@prop write) => { $crate::host::gatt::PROP_WRITE };
    (@prop write_without_response) => { $crate::host::gatt::PROP_WRITE_WITHOUT_RESPONSE };
    (@prop notify) => { $crate::host::gatt::PROP_NOTIFY };
    (@prop indicate) => { $crate::host::gatt::PROP_INDICATE };
    (@sec) => { $crate::host::gatt::Sec::Open };
    (@sec encrypted) => { $crate::host::gatt::Sec::Encrypted };
    (@sec authenticated) => { $crate::host::gatt::Sec::Authenticated };
    ($(#[$meta:meta])* $vis:vis const $db:ident; $($rest:tt)*) => {
        $crate::gatt!(@munch {[$(#[$meta])*] $vis $db} [] [] (1) (0) ($crate::host::gatt::Sec::Open) $($rest)*);
    };
}

/// Characteristic property: the value may be read.
pub const PROP_READ: u8 = 0x02;
/// Characteristic property: the value may be written without a response.
pub const PROP_WRITE_WITHOUT_RESPONSE: u8 = 0x04;
/// Characteristic property: the value may be written with a response.
pub const PROP_WRITE: u8 = 0x08;
/// Characteristic property: the value may be notified.
pub const PROP_NOTIFY: u8 = 0x10;
/// Characteristic property: the value may be indicated.
pub const PROP_INDICATE: u8 = 0x20;

/// Attribute type of a primary service declaration.
pub const PRIMARY_SERVICE: u16 = 0x2800;
/// Attribute type of a secondary service declaration.
pub const SECONDARY_SERVICE: u16 = 0x2801;
/// Attribute type of an include declaration.
pub const INCLUDE: u16 = 0x2802;
/// Attribute type of a characteristic declaration.
pub const CHARACTERISTIC: u16 = 0x2803;
/// Attribute type of a client characteristic configuration descriptor.
pub const CLIENT_CONFIGURATION: u16 = 0x2902;
/// UUID of the Service Changed characteristic.
pub const SERVICE_CHANGED: u16 = 0x2A05;
/// UUID of the Database Hash characteristic.
pub const DATABASE_HASH: u16 = 0x2B2A;
/// Client characteristic configuration bit: notifications.
pub const CCC_NOTIFY: u16 = 0x0001;
/// Client characteristic configuration bit: indications.
pub const CCC_INDICATE: u16 = 0x0002;
/// Client characteristic configuration descriptors a table may have.
pub const CCCD_MAX: u8 = 16;
// The input report and written CCCD bitmaps are u16, one bit per index, and
// the engine reads bit `index` with a shift that must stay below the width.
const _: () = assert!(u32::from(CCCD_MAX) <= u16::BITS, "the CCCD bitmaps are u16");
/// Largest dynamic value: what one Read Response carries at the MTU of 23.
pub const DYNAMIC_MAX: usize = 22;

/// The Bluetooth base UUID with a zero 16-bit part, least significant octet
/// first.
const BASE_UUID: [u8; 16] = [0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0, 0, 0, 0];
/// The characteristic UUID of a HID report.
const REPORT: u16 = 0x2A4D;

/// Who may read and write an attribute: `None` for nobody, otherwise the
/// security the request needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Access {
    /// Security a read needs, `None` if the attribute cannot be read.
    pub read:  Option<Sec>,
    /// Security a write needs, `None` if the attribute cannot be written.
    pub write: Option<Sec>,
}

/// An attribute of the table.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Attr {
    /// What the attribute declares or holds.
    kind:  Kind,
    /// The service's UUID for a service declaration, the characteristic's
    /// for a declaration and the value, the descriptor type for a
    /// descriptor.
    uuid:  Uuid,
    /// The value of a characteristic value or a descriptor.
    value: Value,
}

/// A characteristic of the table, as the application names it to notify or
/// indicate its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Char {
    /// Index of its client characteristic configuration bits.
    cccd:   Option<u8>,
    /// Handle of its value.
    handle: u16,
    /// Its properties.
    props:  u8,
    /// Security its value needs.
    sec:    Sec,
}

/// The attribute table with what the server needs to know about it.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Db {
    /// The attributes, handle 1 first.
    attrs:           &'static [Attr],
    /// Number of client characteristic configuration descriptors.
    cccds:           u8,
    /// The layout hash, the value of the Database Hash characteristic.
    hash:            [u8; 16],
    /// The client characteristic configuration descriptors of the input
    /// reports that notify, one bit for each index ([`input_reports`]).
    input_reports:   u16,
    /// The Service Changed characteristic, if the table has one.
    service_changed: Option<Char>,
}

/// What an attribute declares or holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kind {
    /// A characteristic declaration with the characteristic's properties.
    Characteristic(u8),
    /// A descriptor.
    Descriptor(Access),
    /// A primary service declaration.
    Service,
    /// A characteristic value: who may read and write it, and the security
    /// the characteristic was declared with, which its notifications and
    /// indications need too, even where it can be neither read nor written.
    Value(Access, Sec),
}

/// The security of a link, or the security an attribute needs.
#[derive(Clone, Copy, Debug, Eq)]
#[derive_const(PartialEq)]
#[non_exhaustive]
pub enum Sec {
    /// Encrypted with a key from authenticated pairing (with protection
    /// against a man in the middle).
    Authenticated,
    /// Encrypted.
    Encrypted,
    /// Not encrypted.
    Open,
}

/// The client characteristic configuration of one link: two bits for each
/// descriptor (notify and indicate), and which of them the client wrote on
/// this link.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Subscriptions {
    /// Two bits for each descriptor, descriptor 0 in the lowest.
    values:  u32,
    /// One bit for each descriptor the client wrote on this link.
    written: u16,
}

/// The UUID of a service, a characteristic or a descriptor type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Uuid {
    /// A 128-bit UUID, least significant octet first, as ATT carries it.
    U128(&'static [u8; 16]),
    /// A 16-bit UUID of the Bluetooth base.
    U16(u16),
}

/// The value of a characteristic or a descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// Client characteristic configuration bits with this index, kept for
    /// each link.
    Cccd(u8),
    /// Constant bytes in flash, of any length: Read Blob serves the rest.
    Const(&'static [u8]),
    /// A value the application reads and writes through [`Handler`].
    Dynamic(ValueId),
    /// No value: an indicate-only characteristic such as Service Changed.
    Empty,
    /// The table's layout hash: the Database Hash characteristic.
    Hash,
    /// Takes writes and ignores them, as for the HID Control Point.
    Sink,
    /// This many zeros, as for an input report read before any was sent.
    Zeros(u8),
}

/// Names a dynamic value for [`Handler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValueId(u8);

/// An ATT error code, as an Error Response carries it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AttError(u8);

/// The application's side of the dynamic values ([`Value::Dynamic`]).
///
/// The host calls it from [`crate::host::Host::run`] while it holds its own
/// state, so an implementation must not call into the host: no
/// [`crate::host::Conn`] method, no [`crate::host::Battery::update`] and no
/// other [`crate::host::Host`] method, or the second borrow of the state
/// panics. It may read and write atomics and signal other tasks, which then
/// call the host.
pub trait Handler {
    /// Writes the value `id` into `out` and returns its length, at most
    /// [`DYNAMIC_MAX`].
    ///
    /// # Errors
    ///
    /// The error code for the Error Response.
    fn read(&self, id: ValueId, out: &mut [u8]) -> Result<usize, AttError>;

    /// Takes a write of `data` to the value `id`, `with_response` for a
    /// Write Request. The error of a Write Command is dropped: a command is
    /// never answered.
    ///
    /// # Errors
    ///
    /// The error code for the Error Response.
    fn write(&self, id: ValueId, data: &[u8], with_response: bool) -> Result<(), AttError>;
}

impl Access {
    /// Access from properties or permissions: read with [`PROP_READ`],
    /// write with [`PROP_WRITE`] or [`PROP_WRITE_WITHOUT_RESPONSE`], both
    /// with the security `sec`.
    #[inline]
    #[must_use = "the access is only built"]
    pub const fn from_props(props: u8, sec: Sec) -> Self {
        Self {
            read:  (props & PROP_READ != 0).then_some(sec),
            write: (props & (PROP_WRITE | PROP_WRITE_WITHOUT_RESPONSE) != 0).then_some(sec),
        }
    }
}

impl Attr {
    /// The attribute's access: declarations can be read by anyone and
    /// written by nobody.
    #[inline]
    #[must_use = "the access is only read"]
    pub const fn access(&self) -> Access {
        match self.kind {
            Kind::Characteristic(_) | Kind::Service => Access { read: Some(Sec::Open), write: None },
            Kind::Descriptor(access) | Kind::Value(access, _) => access,
        }
    }

    /// The client characteristic configuration descriptor with the
    /// configuration bits `index`; reading and writing it needs `sec`, the
    /// security of its characteristic.
    #[inline]
    #[must_use = "the attribute is only built"]
    pub const fn cccd(sec: Sec, index: u8) -> Self {
        Self {
            kind:  Kind::Descriptor(Access { read: Some(sec), write: Some(sec) }),
            uuid:  Uuid::U16(CLIENT_CONFIGURATION),
            value: Value::Cccd(index),
        }
    }

    /// The declaration of the characteristic `uuid` with the properties
    /// `props`.
    #[inline]
    #[must_use = "the attribute is only built"]
    pub const fn characteristic(uuid: Uuid, props: u8) -> Self {
        Self { kind: Kind::Characteristic(props), uuid, value: Value::Empty }
    }

    /// The descriptor of type `uuid` holding `value`, read and written as
    /// `perms` ([`PROP_READ`], [`PROP_WRITE`]) allow with the security
    /// `sec`.
    #[inline]
    #[must_use = "the attribute is only built"]
    pub const fn descriptor(uuid: Uuid, perms: u8, sec: Sec, value: Value) -> Self {
        Self { kind: Kind::Descriptor(Access::from_props(perms, sec)), uuid, value }
    }

    /// What the attribute declares or holds.
    #[inline]
    #[must_use = "the kind is only read"]
    pub const fn kind(&self) -> Kind { self.kind }

    /// The declaration of the primary service `uuid`.
    #[inline]
    #[must_use = "the attribute is only built"]
    pub const fn service(uuid: Uuid) -> Self { Self { kind: Kind::Service, uuid, value: Value::Empty } }

    /// The attribute type: 0x2800 for a service, 0x2803 for a
    /// characteristic declaration, the UUID otherwise.
    #[inline]
    #[must_use = "the type is only read"]
    pub const fn type_uuid(&self) -> Uuid {
        match self.kind {
            Kind::Characteristic(_) => Uuid::U16(CHARACTERISTIC),
            Kind::Service => Uuid::U16(PRIMARY_SERVICE),
            Kind::Descriptor(_) | Kind::Value(..) => self.uuid,
        }
    }

    /// The UUID the attribute names: the service's, the characteristic's or
    /// the descriptor type.
    #[inline]
    #[must_use = "the UUID is only read"]
    pub const fn uuid(&self) -> Uuid { self.uuid }

    /// The value of the characteristic `uuid` with the properties `props`;
    /// reading and writing it, as the properties allow, needs `sec`.
    #[inline]
    #[must_use = "the attribute is only built"]
    pub const fn value(uuid: Uuid, props: u8, sec: Sec, value: Value) -> Self {
        Self { kind: Kind::Value(Access::from_props(props, sec), sec), uuid, value }
    }

    /// The stored value: what is read is built from it.
    #[inline]
    #[must_use = "the value is only read"]
    pub const fn value_source(&self) -> Value { self.value }
}

impl AttError {
    /// The attribute cannot be found.
    pub const ATTRIBUTE_NOT_FOUND: Self = Self(0x0A);
    /// The link is encrypted without authentication, or not at all, and the
    /// attribute needs authentication.
    pub const INSUFFICIENT_AUTHENTICATION: Self = Self(0x05);
    /// The link is not encrypted and the attribute needs encryption.
    pub const INSUFFICIENT_ENCRYPTION: Self = Self(0x0F);
    /// The value has a length the attribute does not take.
    pub const INVALID_ATTRIBUTE_VALUE_LENGTH: Self = Self(0x0D);
    /// The handle is 0, past the table, or the range is reversed.
    pub const INVALID_HANDLE: Self = Self(0x01);
    /// The offset is past the end of the value.
    pub const INVALID_OFFSET: Self = Self(0x07);
    /// The PDU is malformed.
    pub const INVALID_PDU: Self = Self(0x04);
    /// The attribute cannot be read.
    pub const READ_NOT_PERMITTED: Self = Self(0x02);
    /// The server does not serve the request.
    pub const REQUEST_NOT_SUPPORTED: Self = Self(0x06);
    /// The request failed for a reason no other code describes.
    pub const UNLIKELY_ERROR: Self = Self(0x0E);
    /// The group type of a Read By Group Type is not a grouping type.
    pub const UNSUPPORTED_GROUP_TYPE: Self = Self(0x10);
    /// The value is out of range.
    pub const VALUE_NOT_ALLOWED: Self = Self(0x13);
    /// The attribute cannot be written.
    pub const WRITE_NOT_PERMITTED: Self = Self(0x03);

    /// An application error, 0x80 to 0x9F; other codes give 0x80.
    #[inline]
    #[must_use = "the error is only built"]
    pub const fn application(code: u8) -> Self { if matches!(code, 0x80..=0x9F) { Self(code) } else { Self(0x80) } }

    /// The code an Error Response carries.
    #[inline]
    #[must_use = "the code is only read"]
    pub const fn code(self) -> u8 { self.0 }
}

impl Char {
    /// Index of its client characteristic configuration bits, `None`
    /// without the descriptor.
    #[inline]
    #[must_use = "the index is only read"]
    pub const fn cccd(&self) -> Option<u8> { self.cccd }

    /// Handle of its value, which notifications and indications carry.
    #[inline]
    #[must_use = "the handle is only read"]
    pub const fn handle(&self) -> u16 { self.handle }

    /// Its properties.
    #[inline]
    #[must_use = "the properties are only read"]
    pub const fn props(&self) -> u8 { self.props }

    /// Security its value needs.
    #[inline]
    #[must_use = "the security is only read"]
    pub const fn sec(&self) -> Sec { self.sec }
}

impl Db {
    /// The attribute with `handle`, `None` for 0 or past the table.
    #[inline]
    #[must_use = "the attribute is only looked up"]
    pub const fn attr(&self, handle: u16) -> Option<&'static Attr> {
        if handle == 0 {
            return None;
        }
        nth(self.attrs, handle.wrapping_sub(1))
    }

    /// The attributes, handle 1 first.
    #[inline]
    #[must_use = "the attributes are only read"]
    pub const fn attrs(&self) -> &'static [Attr] { self.attrs }

    /// Number of client characteristic configuration descriptors.
    #[inline]
    #[must_use = "the number is only read"]
    pub const fn cccds(&self) -> u8 { self.cccds }

    /// The characteristic declared at `handle`. Meant for constants: it
    /// panics, failing the build, if no characteristic is declared there.
    ///
    /// # Panics
    ///
    /// If no characteristic is declared at `handle`.
    #[inline]
    #[must_use = "the characteristic is only looked up"]
    pub const fn characteristic(&self, handle: u16) -> Char {
        let found = char_at(self.attrs, handle);
        assert!(found.is_some(), "no characteristic is declared at this handle");
        // Past the assertion the lookup found one: the stand-in, a value
        // nobody may notify, is never returned.
        found.unwrap_or(Char { cccd: None, handle, props: 0, sec: Sec::Authenticated })
    }

    /// The end handle of the service declared at `handle`: the handle
    /// before the next service declaration, or the last handle of the
    /// table.
    #[inline]
    #[must_use = "the handle is only computed"]
    pub const fn group_end(&self, handle: u16) -> u16 {
        let mut end = handle;
        while let Some(attr) = self.attr(end.saturating_add(1)) {
            if matches!(attr.kind, Kind::Service) || end == u16::MAX {
                break;
            }
            end = end.saturating_add(1);
        }
        end
    }

    /// The layout hash, the value of the Database Hash characteristic.
    #[inline]
    #[must_use = "the hash is only read"]
    pub const fn hash(&self) -> [u8; 16] { self.hash }

    /// The client characteristic configuration descriptors of the input
    /// reports that notify, one bit for each index: the HID reports
    /// (0x2A4D) with the notify property, as `BlueZ` subscribes to each of
    /// them. [`Self::new`] finds them at compile time.
    #[inline]
    #[must_use = "the bits are only read"]
    pub(crate) const fn input_reports(&self) -> u16 { self.input_reports }

    /// The handle of the last attribute: the number of attributes, which
    /// [`Self::new`] checked to fit a handle.
    #[inline]
    #[must_use = "the handle is only read"]
    pub const fn last_handle(&self) -> u16 { self.attrs.len().truncate() }

    /// Whether an attribute of the table needs an authenticated link.
    #[cfg(feature = "passkey")]
    #[inline]
    #[must_use = "the answer is only computed"]
    pub const fn needs_authentication(&self) -> bool {
        let mut rest = self.attrs;
        while let Some((attr, tail)) = rest.split_first() {
            if needs_authentication(attr.kind) {
                return true;
            }
            rest = tail;
        }
        false
    }

    /// The table `attrs`, with its hash. Meant for constants: it panics,
    /// failing the build, if a characteristic that notifies or indicates
    /// lacks its client characteristic configuration descriptor, if
    /// another has one, if the descriptor indices do not count up from 0,
    /// if an attribute needs authentication ([`Sec::Authenticated`])
    /// without the feature `passkey`, or if the table is too large.
    ///
    /// Without the feature `passkey` the host pairs with Just Works only,
    /// so no link is ever authenticated: an attribute that needs it would
    /// answer Insufficient Authentication (0x05) on every link, on which
    /// `BlueZ` pairs again with protection against a man in the middle
    /// required, and that pairing fails. With the feature, `Host::new`
    /// refuses such a table unless its configuration pairs with Passkey
    /// Entry.
    ///
    /// # Panics
    ///
    /// If the table breaks one of these rules.
    #[inline]
    #[must_use = "the table is only built"]
    pub const fn new(attrs: &'static [Attr]) -> Self {
        assert!(attrs.len() < 0xFFFF, "the table has more attributes than handles");
        let cccds = check(attrs);
        Self {
            attrs,
            cccds,
            hash: hash::layout(attrs),
            input_reports: input_reports(attrs),
            service_changed: find_service_changed(attrs),
        }
    }

    /// The Service Changed characteristic, if the table has one.
    #[inline]
    #[must_use = "the characteristic is only read"]
    pub const fn service_changed(&self) -> Option<Char> { self.service_changed }
}

impl Sec {
    /// Whether a link of security `level` meets this requirement.
    #[inline]
    #[must_use = "the comparison is only computed"]
    pub const fn met_by(self, level: Self) -> bool { level.rank() >= self.rank() }

    /// The name of the level, for a defmt log line (`{=istr}`): interned,
    /// so the string stays in the `.defmt` section, which takes no flash.
    #[cfg(feature = "defmt")]
    #[inline]
    #[must_use = "the name is only read"]
    pub fn name(self) -> defmt::Str {
        match self {
            Self::Authenticated => defmt::intern!("Authenticated"),
            Self::Encrypted => defmt::intern!("Encrypted"),
            Self::Open => defmt::intern!("Open"),
        }
    }

    /// Rank of the level: open below encrypted below authenticated.
    const fn rank(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Encrypted => 1,
            Self::Authenticated => 2,
        }
    }
}

impl Subscriptions {
    /// The bits as the bond keeps them: two for each descriptor.
    #[inline]
    #[must_use = "the bits are only read"]
    pub const fn bits(self) -> u32 { self.values }

    /// Configuration restored from a bond's `bits`, as written on no link
    /// yet.
    #[inline]
    #[must_use = "the configuration is only built"]
    pub const fn from_bits(bits: u32) -> Self { Self { values: bits, written: 0 } }

    /// Whether the client asked for indications on the descriptor `index`.
    #[inline]
    #[must_use = "the bit is only read"]
    pub const fn indicating(self, index: u8) -> bool { self.value(index) & CCC_INDICATE != 0 }

    /// Whether the client wrote the descriptor `index` on this link.
    #[inline]
    #[must_use = "the bit is only read"]
    pub const fn is_written(self, index: u8) -> bool {
        self.written.checked_shr(u32::from(index)).unwrap_or(0) & 1 != 0
    }

    /// No subscriptions.
    #[inline]
    #[must_use = "the configuration is only built"]
    pub const fn new() -> Self { Self { values: 0, written: 0 } }

    /// Whether the client asked for notifications on the descriptor
    /// `index`.
    #[inline]
    #[must_use = "the bit is only read"]
    pub const fn notifying(self, index: u8) -> bool { self.value(index) & CCC_NOTIFY != 0 }

    /// Stores the bits of `value` that `props` allow for the descriptor
    /// `index`, as written on this link.
    #[inline]
    pub const fn set(&mut self, index: u8, value: u16, props: u8) {
        if index >= CCCD_MAX {
            return;
        }
        let mut allowed: u32 = 0;
        if props & PROP_NOTIFY != 0 {
            allowed |= u32::from(CCC_NOTIFY);
        }
        if props & PROP_INDICATE != 0 {
            allowed |= u32::from(CCC_INDICATE);
        }
        let shift = u32::from(index).saturating_mul(2);
        let mask = u32::checked_shl(3, shift).unwrap_or(0);
        let bits = (u32::from(value) & allowed).checked_shl(shift).unwrap_or(0);
        self.values = (self.values & !mask) | bits;
        self.written |= u16::checked_shl(1, u32::from(index)).unwrap_or(0);
    }

    /// The value of the descriptor `index`, as a Read gives it.
    #[inline]
    #[must_use = "the value is only read"]
    pub const fn value(self, index: u8) -> u16 {
        (self.values.checked_shr(u32::from(index).saturating_mul(2)).unwrap_or(0) & 3).truncate()
    }
}

impl Uuid {
    /// Whether `raw`, a UUID as a request carries it (2 or 16 octets, least
    /// significant first), names this UUID. The 128-bit form of a 16-bit
    /// UUID matches too.
    #[inline]
    #[must_use = "the comparison is only computed"]
    pub const fn matches(&self, raw: &[u8]) -> bool {
        match (*self, raw.len()) {
            (Self::U16(short), 2) => raw == short.to_le_bytes(),
            (_, 16) => raw == self.to_u128(),
            _ => false,
        }
    }

    /// The 128-bit form, least significant octet first.
    #[inline]
    #[must_use = "the UUID is only converted"]
    pub const fn to_u128(&self) -> [u8; 16] {
        match *self {
            Self::U16(short) => {
                let mut bytes = BASE_UUID;
                let [low, high] = short.to_le_bytes();
                bytes[12] = low;
                bytes[13] = high;
                bytes
            },
            Self::U128(long) => *long,
        }
    }

    /// Length on the air: 2 or 16 octets.
    #[inline]
    #[must_use = "the length is only read"]
    pub const fn wire_len(&self) -> usize {
        match *self {
            Self::U16(_) => 2,
            Self::U128(_) => 16,
        }
    }

    /// Writes the UUID as ATT carries it into the start of `out` and
    /// returns its length, or 0 if `out` is too short.
    #[inline]
    pub const fn write(&self, out: &mut [u8]) -> usize {
        match *self {
            Self::U16(short) => copy(out, &short.to_le_bytes()),
            Self::U128(long) => copy(out, long),
        }
    }
}

impl ValueId {
    /// The index the application gave the value.
    #[inline]
    #[must_use = "the index is only read"]
    pub const fn index(self) -> u8 { self.0 }

    /// The dynamic value with the application's index `index`.
    #[inline]
    #[must_use = "the name is only built"]
    pub const fn new(index: u8) -> Self { Self(index) }
}

/// The client characteristic configuration descriptor index of the
/// characteristic whose value is at `handle`: the first descriptor before
/// the next declaration.
const fn cccd_after(attrs: &'static [Attr], handle: u16) -> Option<u8> {
    let mut next = handle;
    while let Some(attr) = nth(attrs, next) {
        match (attr.kind, attr.value) {
            (Kind::Characteristic(_) | Kind::Service, _) => return None,
            (Kind::Descriptor(_), Value::Cccd(index)) => return Some(index),
            _ => {},
        }
        next = next.saturating_add(1);
        if next == u16::MAX {
            return None;
        }
    }
    None
}

/// Checks the descriptors of the table and returns their number; see
/// [`Db::new`].
const fn check(attrs: &[Attr]) -> u8 {
    let mut cccds: u8 = 0;
    let mut props: u8 = 0;
    let mut has_cccd = false;
    let mut rest = attrs;
    while let Some((attr, tail)) = rest.split_first() {
        #[cfg(not(feature = "passkey"))]
        assert!(
            !needs_authentication(attr.kind),
            "no attribute may need authentication: the host pairs with Just Works"
        );
        match (attr.kind, attr.value) {
            (Kind::Characteristic(next), _) => {
                check_cccd(props, has_cccd);
                props = next;
                has_cccd = false;
            },
            (Kind::Service, _) => {
                check_cccd(props, has_cccd);
                props = 0;
                has_cccd = false;
            },
            (_, Value::Cccd(index)) => {
                assert!(
                    !has_cccd && index == cccds && cccds < CCCD_MAX,
                    "a characteristic has two configuration descriptors, or their indices skip"
                );
                has_cccd = true;
                cccds = cccds.saturating_add(1);
            },
            _ => {},
        }
        rest = tail;
    }
    check_cccd(props, has_cccd);
    cccds
}

/// Checks that a characteristic with the properties `props` has a client
/// characteristic configuration descriptor exactly if it notifies or
/// indicates.
const fn check_cccd(props: u8, has_cccd: bool) {
    assert!(
        (props & (PROP_NOTIFY | PROP_INDICATE) != 0) == has_cccd,
        "a characteristic that notifies or indicates needs one configuration descriptor, any other none"
    );
}

/// Whether an attribute of `kind` needs authentication for anything.
const fn needs_authentication(kind: Kind) -> bool {
    const fn authenticated(sec: Option<Sec>) -> bool { matches!(sec, Some(Sec::Authenticated)) }
    match kind {
        Kind::Characteristic(_) | Kind::Service => false,
        Kind::Descriptor(access) => authenticated(access.read) || authenticated(access.write),
        Kind::Value(access, sec) => {
            authenticated(access.read) || authenticated(access.write) || authenticated(Some(sec))
        },
    }
}

/// Copies `source` into the start of `out` and returns its length, or 0 if
/// `out` is too short.
const fn copy(out: &mut [u8], source: &[u8]) -> usize {
    out.get_mut(..source.len()).map_or(0, const |target| {
        target.copy_from_slice(source);
        source.len()
    })
}

/// The characteristic declared at `handle` of `attrs`, `None` if none is.
const fn char_at(attrs: &'static [Attr], handle: u16) -> Option<Char> {
    let declaration = nth(attrs, handle.wrapping_sub(1))?;
    let value = nth(attrs, handle)?;
    let (Kind::Characteristic(props), Kind::Value(_, sec)) = (declaration.kind, value.kind) else { return None };
    let value_handle = handle.saturating_add(1);
    Some(Char { cccd: cccd_after(attrs, value_handle), handle: value_handle, props, sec })
}

/// The Service Changed characteristic of `attrs`, if it has one.
const fn find_service_changed(attrs: &'static [Attr]) -> Option<Char> {
    let mut handle: u16 = 1;
    while let Some(attr) = nth(attrs, handle.wrapping_sub(1)) {
        if let (Kind::Characteristic(_), Uuid::U16(SERVICE_CHANGED)) = (attr.kind, attr.uuid) {
            return char_at(attrs, handle);
        }
        if handle == u16::MAX {
            return None;
        }
        handle = handle.saturating_add(1);
    }
    None
}

/// The client characteristic configuration descriptors of the input reports
/// of `attrs` that notify, one bit for each index: the HID reports (0x2A4D)
/// with the notify property, as `BlueZ` subscribes to each of them.
const fn input_reports(attrs: &[Attr]) -> u16 {
    let mut inputs: u16 = 0;
    let mut report = false;
    let mut rest = attrs;
    while let Some((attr, tail)) = rest.split_first() {
        match (attr.kind, attr.value) {
            (Kind::Characteristic(props), _) => {
                report = matches!(attr.uuid, Uuid::U16(REPORT)) && props & PROP_NOTIFY != 0;
            },
            (Kind::Service, _) => report = false,
            (Kind::Descriptor(_), Value::Cccd(index)) if report => {
                inputs |= u16::checked_shl(1, u32::from(index)).unwrap_or(0);
            },
            _ => {},
        }
        rest = tail;
    }
    inputs
}

/// The attribute at `index` of `attrs`.
const fn nth(attrs: &'static [Attr], index: u16) -> Option<&'static Attr> {
    let (_, rest) = attrs.split_at_checked(usize::from(index))?;
    rest.first()
}

/// The Peripheral Preferred Connection Parameters value of `range`:
/// shortest and longest interval, latency and timeout, each least
/// significant octet first.
#[inline]
#[must_use = "the value is only built"]
pub const fn ppcp(range: ParamRange) -> [u8; 8] {
    let [min0, min1] = range.interval_min.to_le_bytes();
    let [max0, max1] = range.interval_max.to_le_bytes();
    let [latency0, latency1] = range.latency.to_le_bytes();
    let [timeout0, timeout1] = range.timeout.to_le_bytes();
    [min0, min1, max0, max1, latency0, latency1, timeout0, timeout1]
}

#[cfg(test)] mod tests;
