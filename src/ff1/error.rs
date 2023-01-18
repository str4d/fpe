use core::fmt;

/// Error indicating that a radix was not in the supported range of values for FF1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRadix(pub(super) u32);

impl fmt::Display for InvalidRadix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The radix {} is not in the range 2..=(1 << 16)", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidRadix {}

/// Errors that can occur while using FF1 for encryption or decryption.
#[derive(Clone, Copy, Debug)]
pub enum NumeralStringError {
    /// The numeral string was not compatible with the configured radix.
    InvalidForRadix(u32),
}

impl fmt::Display for NumeralStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NumeralStringError::InvalidForRadix(radix) => {
                write!(f, "The given numeral string is invalid for radix {}", radix)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NumeralStringError {}
