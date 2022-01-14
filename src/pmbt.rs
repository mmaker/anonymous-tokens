use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use zkp::Transcript;

use crate::errors::VerificationError;
use crate::Ticket;

use crate::or_dleq;

pub struct KeyPair {
    pub(crate) pp: PublicParams,
    pub(crate) sk: [[Scalar; 2]; 2],
}

#[derive(Clone)]
pub struct PublicParams {
    pub(crate) pk: [RistrettoPoint; 2],
    pub(crate) gen: [RistrettoPoint; 2],
}

impl<'a> From<&'a KeyPair> for PublicParams {
    fn from(kp: &'a KeyPair) -> PublicParams {
        kp.pp.clone()
    }
}

impl KeyPair {
    pub fn generate<R>(mut csrng: &mut R) -> KeyPair
    where
        R: RngCore + CryptoRng,
    {
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

        let pp = PublicParams { pk, gen };
        KeyPair { pp, sk }
    }

    pub fn sign<R>(&self, csrng: &mut R, blind_token: &[u8], b: usize) -> Option<TokenSigned>
    where
        R: RngCore + CryptoRng,
    {
        let mut s = [0u8; 32];
        csrng.fill_bytes(&mut s);

        // XXX this should return an option point
        let alt_gens = [
            CompressedRistretto::from_slice(&blind_token[..32]).decompress()?,
            RistrettoPoint::hash_from_bytes::<Sha512>(&s),
        ];
        let signature = RistrettoPoint::multiscalar_mul(&self.sk[b], &alt_gens);
        let mut transcript = Transcript::new(b"OR-DLEQ");
        let proof = or_dleq::prove_compact(
            &mut transcript,
            or_dleq::ProveAssignments {
                x: &self.sk[b][0],
                y: &self.sk[b][1],
                b: &b,
                G: &self.pp.gen[0],
                H: &self.pp.gen[1],
                T: &alt_gens[0],
                S: &alt_gens[1],
                W: &signature,
                X0: &self.pp.pk[0],
                X1: &self.pp.pk[1],
            },
        );
        Some(TokenSigned {
            s,
            signature,
            proof,
        })
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
    pub(crate) multiplicative_blind: Scalar,
}

pub struct TokenBlinded {
    secret: TokenSecret,
    public: RistrettoPoint,
    pp: PublicParams,
}

impl TokenBlinded {
    pub fn unsafe_unblind(&self, ts: &TokenSigned) -> Result<Token, or_dleq::errors::ProofError> {
        let mut transcript = Transcript::new(b"OR-DLEQ");
        let hashed_S = RistrettoPoint::hash_from_bytes::<Sha512>(&ts.s);
        let ticket = self.secret.ticket;
        // XXX: fix generation of S, it should integrate T'
        let signature = self.secret.multiplicative_blind * ts.signature;
        let S = self.secret.multiplicative_blind * hashed_S;

        let verification = or_dleq::verify_compact(
            &ts.proof,
            &mut transcript,
            or_dleq::VerifyAssignments {
                X0: &self.pp.pk[0].compress(),
                X1: &self.pp.pk[1].compress(),
                T: &self.public.compress(),
                S: &hashed_S.compress(),
                G: &self.pp.gen[0].compress(),
                H: &self.pp.gen[1].compress(),
                W: &ts.signature.compress(),
            },
        );
        verification.map(|_| Token {
            ticket,
            S,
            signature,
        })
    }

    pub fn unblind(self, ts: TokenSigned) -> Result<Token, or_dleq::errors::ProofError> {
        self.unsafe_unblind(&ts)
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        // XXX Fix this
        let fst = self.public.compress().to_bytes();
        let snd = self.public.compress().to_bytes();
        let mut ret = [0u8; 64];

        ret[..32].clone_from_slice(&fst);
        ret[32..].clone_from_slice(&snd);
        ret
    }
}

impl TokenSecret {
    pub fn generate<R>(mut csrng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let mut ticket = [0u8; 32];
        csrng.fill_bytes(&mut ticket);
        let multiplicative_blind = Scalar::random(&mut csrng);
        Self {
            ticket,
            multiplicative_blind,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenSigned {
    s: Ticket,
    signature: RistrettoPoint,
    proof: crate::or_dleq::OrDleqProof,
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
    where
        R: RngCore + CryptoRng,
    {
        let secret = TokenSecret::generate(&mut csrng);
        let hashed_ticket = RistrettoPoint::hash_from_bytes::<Sha512>(&secret.ticket);
        let public = secret.multiplicative_blind.invert() * hashed_ticket;

        // XXX we can use lifetimes here
        let pp = self.clone();
        TokenBlinded { secret, public, pp }
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
        assert!(signed_token.is_some());
        let token = blinded_token.unblind(signed_token.unwrap());
        assert!(token.is_ok());
        assert!(keypair.verify(&token.unwrap()).is_ok());
    }
}
