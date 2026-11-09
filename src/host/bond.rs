//! The bond with the one central the device pairs with.
//!
//! A bond holds the central's identity address and identity resolving key,
//! the long term key, whether pairing was authenticated, the client
//! characteristic configuration bits and part of the table's layout hash. It
//! converts to and from a fixed number of bytes, which the firmware stores in
//! flash.
