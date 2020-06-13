extern crate curve25519_dalek;
extern crate merlin;
extern crate rand_core;
#[macro_use]
extern crate zkp;

#[allow(non_snake_case)]
pub mod pp;
#[allow(non_snake_case)]
pub mod ppnozk;

//#[allow(non_snake_case)]
//pub mod construction3;
//#[allow(non_snake_case)]
//pub mod construction4;

pub mod errors;

/// A ticket is the unique identifier associated to an anonymous token.
type Ticket = [u8; 32];
