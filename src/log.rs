//! Logging over RTT with the `defmt` feature, compiled out without it.
//!
//! Each macro logs at the defmt level of its name: `warn!` for failures,
//! refusals and timeouts, `info!` for the rest. Which levels a build keeps is
//! the firmware's choice, through `DEFMT_LOG` (for example `nrf_ble=info`).

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

/// Logs at warn level.
macro_rules! warn {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[cfg(feature = "defmt")]
        {
            defmt::warn!($fmt $(, $arg)*);
        }
        #[cfg(not(feature = "defmt"))]
        {
            $(_ = &$arg;)*
        }
    }};
}
