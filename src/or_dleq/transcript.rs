#![allow(non_snake_case)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub trait OrDleqTranscript {
    /// Append a domain separator for OR and OR-batched.
    fn domain_sep(&mut self);
    fn domain_sep_batched(&mut self, n: usize);

    /// Append a `scalar` with the given lebel.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Append a `point` with the given label.
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint);

    /// Compute a `label`ed challenge scalar from the given commitments and the choice bit.
    fn get_challenge(&mut self, label: &'static [u8])  -> Scalar;
}


impl OrDleqTranscript for Transcript {

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.append_message(label, point.compress().as_bytes());
    }

    fn get_challenge(&mut self, label: &'static [u8])  -> Scalar {
        let mut bytes = [0; 64];
        self.challenge_bytes(label, &mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }
}
