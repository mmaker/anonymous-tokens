use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_COMPRESSED};
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use serde::{Serialize, Deserialize};
use sha2::Sha512;

use crate::errors::VerificationError;

type Ticket = [u8; 32];

pub struct KeyPair {
    pub(crate) pp: PublicParams,
    pub(crate) sk: [[Scalar; 2]; 2],
}

#[derive(Clone, Copy)]
pub struct PublicParams {
    pk: [RistrettoPoint; 2],
    gen: [RistrettoPoint; 2],
}

impl KeyPair {
    pub fn generate<R>(mut csrng: &mut R) -> KeyPair
    where R: RngCore + CryptoRng {
        let sk = [
            [Scalar::random(&mut csrng), Scalar::random(&mut csrng)],
            [Scalar::random(&mut csrng), Scalar::random(&mut csrng)],
        ];
        let gen = [
            RISTRETTO_BASEPOINT_POINT,
            RistrettoPoint::hash_from_bytes::<Sha512>(&RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()),
        ];
        let pk = [
            RistrettoPoint::multiscalar_mul(&sk[0], &gen),
            RistrettoPoint::multiscalar_mul(&sk[1], &gen),
        ];
        let pp = PublicParams {pk, gen};
        KeyPair { pp, sk }
    }
}


impl<'a> From::<&'a KeyPair> for PublicParams {
    fn from(kp: &'a KeyPair) -> PublicParams {
        kp.pp
    }
}


impl KeyPair {
    pub fn sign<R>(&self, csrng: &mut R, blind_token: &[u8; 32], b: usize) -> TokenSigned
    where R: RngCore + CryptoRng {
        let mut s = [0u8; 32];
        csrng.fill_bytes(&mut s);

        // XXX this should return an option point
        let alt_gens = [
            CompressedRistretto(*blind_token).decompress().unwrap(),
            RistrettoPoint::hash_from_bytes::<Sha512>(&s),
        ];
        let signature = RistrettoPoint::multiscalar_mul(&self.sk[b], &alt_gens);
        TokenSigned {s, signature}
    }

    pub fn verify(&self, token: &Token) -> Result<usize, VerificationError> {
        let alt_gens = [
            RistrettoPoint::hash_from_bytes::<Sha512>(&token.ticket),
            token.S,
        ];

        let possible_signatures = (
            RistrettoPoint::multiscalar_mul(&self.sk[0], &alt_gens),
            RistrettoPoint::multiscalar_mul(&self.sk[1], &alt_gens),
        );

        if token.signature == possible_signatures.0 {
            Result::Ok(0)
        } else if token.signature == possible_signatures.1 {
            Result::Ok(1)
        } else {
            Result::Err(VerificationError)
        }
    }
}


struct TokenSecret {
    pub(crate) ticket: Ticket,
    pub(crate) blind: Scalar,
}

pub struct TokenBlinded {
    secret: TokenSecret,
    public: RistrettoPoint,
    pp: PublicParams,
}

impl TokenBlinded {
    pub fn unblind(self, ts: TokenSigned) ->  Result<Token, zkp::ProofError> {
            Ok(Token {
                ticket: self.secret.ticket,
                signature: self.secret.blind * ts.signature,
                S: self.secret.blind * RistrettoPoint::hash_from_bytes::<Sha512>(&ts.s),
            })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        return self.public.compress().to_bytes()
    }

}
impl TokenSecret {
    pub fn generate<R>(mut csrng: &mut R) -> Self
    where R: RngCore + CryptoRng {
        let mut ticket = [0u8; 32];
        csrng.fill_bytes(&mut ticket);
        let blind = Scalar::random(&mut csrng);
        Self {ticket, blind}
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenSigned {
    s: Ticket,
    signature: RistrettoPoint,
}

impl TokenSigned {
    pub fn to_bytes(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    pub fn from_bytes(s: &[u8]) -> bincode::Result<Self> {
        bincode::deserialize(&s)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    ticket: Ticket,
    S: RistrettoPoint,
    signature: RistrettoPoint,
}

impl PublicParams {
    pub fn generate_token<R>(&self, mut csrng: &mut R) -> TokenBlinded
    where R: RngCore + CryptoRng {
        let secret = TokenSecret::generate(&mut csrng);
        let public = secret.blind.invert() * RistrettoPoint::hash_from_bytes::<Sha512>(&secret.ticket);
        // XXX we can use lifetimes here
        let pp = *self;
        TokenBlinded {secret, public, pp}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let mut csrng = rand::rngs::OsRng;
        let keypair = KeyPair::generate(&mut csrng);

        let pp = PublicParams::from(&keypair);
        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&mut csrng, &blinded_token.to_bytes(), 0);
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        assert!(keypair.verify(&token.unwrap()).is_ok());
    }
}
