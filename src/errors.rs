use std::fmt;
use std::error;

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



