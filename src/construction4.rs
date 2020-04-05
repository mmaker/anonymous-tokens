use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zkp::Transcript;

use crate::errors::VerificationError;

define_proof! {dlog, "DLOG Knowledge", (x), (X), (G) : X = (x * G)}

type Ticket = [u8; 32];

pub struct KeyPair {
    pub(crate) pp: PublicParams,
    pub(crate) sk: Scalar,
}

#[derive(Clone)]
pub struct PublicParams {
    pk: RistrettoPoint,
    generator: RistrettoPoint,
    // XXX. this can be made into one?
    proof: zkp::BatchableProof,
}

impl KeyPair {
    pub fn generate<R>(mut csrng: &mut R) -> KeyPair
    where
        R: RngCore + CryptoRng,
    {
        let sk = Scalar::random(&mut csrng);
        let generator = RISTRETTO_BASEPOINT_POINT;
        let pk = sk * generator;
        let mut transcript = Transcript::new(b"construction5");
        let (proof, _) = dlog::prove_batchable(
            &mut transcript,
            dlog::ProveAssignments {
                x: &sk,
                G: &generator,
                X: &pk,
            },
        );
        let pp = PublicParams {
            pk,
            generator,
            proof,
        };
        KeyPair { pp, sk }
    }
}

impl<'a> From<&'a KeyPair> for PublicParams {
    fn from(kp: &'a KeyPair) -> PublicParams {
        kp.pp.clone()
    }
}

impl KeyPair {
    pub fn sign<R>(&self, csrng: &mut R, blind_token: &[u8; 32]) -> TokenSigned
    where
        R: RngCore + CryptoRng,
    {
        let mut s = [0u8; 32];
        csrng.fill_bytes(&mut s);

        // XXX this should return an option point
        let alt_gen = CompressedRistretto(*blind_token).decompress().unwrap();
        let signature = self.sk * alt_gen;
        TokenSigned { s, signature }
    }

    pub fn verify(&self, token: &Token) -> Result<(), VerificationError> {
        let expected_signature = self.sk * RistrettoPoint::hash_from_bytes::<Sha512>(&token.ticket);
        if expected_signature == token.signature {
            Result::Ok(())
        } else {
            Result::Err(VerificationError)
        }
    }
}

struct TokenSecret {
    pub(crate) ticket: Ticket,
    pub(crate) blind: [Scalar; 2],
}

pub struct TokenBlinded {
    secret: TokenSecret,
    public: RistrettoPoint,
    pp: PublicParams,
}

impl TokenBlinded {
    pub fn unblind(self, ts: TokenSigned) -> Result<Token, zkp::ProofError> {
        let W = self.secret.blind[0].invert() * ts.signature + self.secret.blind[1] * self.pp.pk;

        Ok(Token {
            ticket: self.secret.ticket,
            signature: W,
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        return self.public.compress().to_bytes();
    }
}
impl TokenSecret {
    pub fn generate<R>(mut csrng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let mut ticket = [0u8; 32];
        csrng.fill_bytes(&mut ticket);
        // XXX ugly
        let blind = [Scalar::random(&mut csrng), Scalar::random(&mut csrng)];
        Self { ticket, blind }
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
    signature: RistrettoPoint,
}

impl PublicParams {
    pub fn generate_token<R>(&self, mut csrng: &mut R) -> TokenBlinded
    where
        R: RngCore + CryptoRng,
    {
        let secret = TokenSecret::generate(&mut csrng);
        let T = RistrettoPoint::hash_from_bytes::<Sha512>(&secret.ticket);
        let public = secret.blind[0] * (T - secret.blind[1] * self.generator);
        let pp = self.clone();
        // XXX we can use lifetimes here?
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
        let signed_token = keypair.sign(&mut csrng, &blinded_token.to_bytes());
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        assert!(keypair.verify(&token.unwrap()).is_ok());
    }
}
