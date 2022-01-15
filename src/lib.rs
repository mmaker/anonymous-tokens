//! This library holds the reference implementation for a variety of single-use anonymous tokens.
//!
//! An anonymous token is a single-use lightweight anonymous credential that can be used to signal
//! trust while preserving anonymity.
//!

/// A ticket is the unique identifier associated to an anonymous token.
/// It is the serial number that allows to check if the token was already spent.
type Ticket = [u8; 32];

extern crate curve25519_dalek;
extern crate merlin;
#[macro_use]
extern crate zkp;

#[macro_use]
extern crate serde;

mod errors;
pub use errors::VerificationError;

pub mod pk;
pub mod sk;
