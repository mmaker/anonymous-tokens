//! Collection of public-key anonymous tokens.
//!
//! This module contains public-key anonymous tokens, that is tokens
//! that can be publicly verified, whith (potentially) private metadata that
//! can be only accessible to the party holding the secret issuing key.
//! The private medatata can't be read by any other party, including the user.

pub mod blor;
