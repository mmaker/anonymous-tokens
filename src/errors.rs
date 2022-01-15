use std::error;
use std::fmt;

/// An error during verification, indicating verification failure.
#[derive(Debug, Clone)]
pub struct VerificationError;

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "verification failed")
    }
}

impl error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
