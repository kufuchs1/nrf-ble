//! The hash of the attribute table's layout, computed as a constant.
//!
//! Not written yet: the ATT stage fills this module. What it is to do:
//! compute the Database Hash of the table's layout, over each attribute's
//! handle, type and, for declarations, value, as the Core specification
//! defines it.
//!
//! The hash only spares BlueZ the rediscovery of an unchanged layout. It does
//! not protect a cached value: BlueZ keeps its cached HID Report Map when only
//! the hash changes, and also keeps a cached service whose start handle, UUID
//! and number of handles are the same. A firmware that changes the Report Map
//! without changing the layout therefore changes the HID service's number of
//! handles too (a filler descriptor whose presence follows a revision), or the
//! central has to pair again.
