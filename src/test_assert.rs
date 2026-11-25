//! Assertions of the tests that hand back the value they check.
//!
//! A test that needs the value inside an `Option` or a `Result` asserts that
//! it is there and goes on with it. Where it is missing, the assertion fails
//! the test; the `return` after it is never taken, and limits the macros to
//! functions that return `()`.

/// The value inside the `Option` `$option`, asserted to be `Some`, with
/// the message `$message` if it is not.
macro_rules! assert_some {
    ($option:expr $(,)?) => {
        assert_some!($option, "{} is None", stringify!($option))
    };
    ($option:expr, $($message:tt)+) => {{
        let option = $option;
        assert!(option.is_some(), $($message)+);
        let Some(value) = option else { return };
        value
    }};
}

/// The value inside the `Result` `$result`, asserted to be `Ok`, with the
/// message `$message` if it is not.
macro_rules! assert_ok {
    ($result:expr $(,)?) => {
        assert_ok!($result, "{} is an error", stringify!($result))
    };
    ($result:expr, $($message:tt)+) => {
        assert_some!($result.ok(), $($message)+)
    };
}
