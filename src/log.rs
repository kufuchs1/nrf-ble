//! Logging over RTT with the `defmt` feature, compiled out without it.

/// Logs at info level.
macro_rules! info {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[cfg(feature = "defmt")]
        {
            defmt::info!($fmt $(, $arg)*);
        }
        #[cfg(not(feature = "defmt"))]
        {
            $(_ = &$arg;)*
        }
    }};
}
