extern crate curve25519_dalek;
extern crate merlin;
extern crate rand_core;
#[macro_use]
extern crate zkp;

#[macro_use]
extern crate serde;

#[allow(non_snake_case)]
pub mod pp;
#[allow(non_snake_case)]
pub mod ppnozk;

#[allow(non_snake_case)]
pub mod pmbt;

#[allow(non_snake_case)]
pub mod pmbtnozk;

mod or_dleq;
//#[allow(non_snake_case)]
//pub mod construction4;

pub mod errors;

/// A ticket is the unique identifier associated to an anonymous token.
type Ticket = [u8; 32];
