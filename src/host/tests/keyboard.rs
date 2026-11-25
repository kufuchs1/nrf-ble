//! A keyboard's table for the Passkey Entry tests: an input report that
//! needs an authenticated link.

use crate::host::gatt::Value;

#[cfg(not(feature = "eatt"))]
crate::gatt! {
    /// The table.
    pub const DB;
    service 0x1812 {
        /// The keyboard input report.
        char KEYS: 0x2A4D [read, notify; authenticated] = Value::Zeros(8);
        ccc;
    }
}

// With `eatt` the host needs the feature characteristics too: after the
// report, so that its handles stay.
#[cfg(feature = "eatt")]
crate::gatt! {
    /// The table.
    pub const DB;
    service 0x1812 {
        /// The keyboard input report.
        char KEYS: 0x2A4D [read, notify; authenticated] = Value::Zeros(8);
        ccc;
    }
    service 0x1801 {
        char 0x2B29 [read, write] = Value::ClientFeatures;
        char 0x2B3A [read] = Value::ServerFeatures;
    }
}
