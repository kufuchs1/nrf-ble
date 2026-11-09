//! The bond with the one central the device pairs with.
//!
//! Not written yet: the security manager stage fills this module. What it is
//! to do: hold the central's identity address and identity resolving key, the
//! long term key, whether pairing was authenticated and the client
//! characteristic configuration bits, and convert to and from a fixed number
//! of bytes, which the firmware stores in flash.
//!
//! It is to keep part of the table's layout hash only for a table with the
//! Service Changed characteristic. The Spotlight table has none, so its bond
//! has no such part.
