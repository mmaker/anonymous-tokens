//! Collection of secret-key anonymous tokens.
//!
//! This module contains Privacy Pass [[DGS+18](https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf)]
//! as well as some of its extensions developed in [[KLOR20](https://eprint.iacr.org/2020/072.pdf)].
//! In this module, we consider anonymous tokens where the issuer and the verifier possess the same key material, and
//! hence the verification is expected to be done by the same party.

pub mod or_dleq;

#[allow(non_snake_case)]
pub mod pmbt;
#[allow(non_snake_case)]
pub mod pmbtnozk;
#[allow(non_snake_case)]
pub mod pp;
#[allow(non_snake_case)]
pub mod ppnozk;
