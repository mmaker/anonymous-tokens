use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zkp::Transcript;

use crate::errors::VerificationError;
use crate::Ticket;

define_proof! {dleq, "DLEQ Proof", (x), (X, T, W), (G) : X = (x * G), W = (x * T)}

pub struct KeyPair {
    pub(crate) pp: PublicParams,
    pub(crate) sk: Scalar,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PublicParams {
    pub(crate) pk: RistrettoPoint,
    pub(crate) G: RistrettoPoint,
}

impl<'a> From<&'a KeyPair> for PublicParams {
    fn from(kp: &'a KeyPair) -> PublicParams {
        kp.pp
    }
}

impl KeyPair {
    pub fn generate<R>(mut csrng: &mut R) -> KeyPair
    where
        R: RngCore + CryptoRng,
    {
        let sk = Scalar::random(&mut csrng);
        let G = RISTRETTO_BASEPOINT_POINT;
        let pk = sk * G;
        let pp = PublicParams { pk, G };
        KeyPair { sk, pp }
    }

    pub fn sign(&self, blind_token_bytes: &[u8; 32]) -> Option<TokenSigned> {
        let T = CompressedRistretto(*blind_token_bytes).decompress()?;
        let signature = self.sk * T;
        let mut transcript = Transcript::new(b"DLEQ");
        let (proof, _) = dleq::prove_batchable(
            &mut transcript,
            dleq::ProveAssignments {
                x: &self.sk,
                X: &self.pp.pk,
                T: &T,
                G: &self.pp.G,
                W: &signature,
            },
        );
        Some(TokenSigned { signature, proof })
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

#[derive(Serialize, Deserialize)]
pub struct TokenSecret {
    pub(crate) ticket: Ticket,
    pub(crate) blind: Scalar,
}

pub struct TokenBlinded {
    secret: TokenSecret,
    public: RistrettoPoint,
    pp: PublicParams,
}

impl TokenBlinded {
    pub fn unsafe_unblind(&self, ts: &TokenSigned) -> Result<Token, zkp::ProofError> {
        let mut transcript = Transcript::new(b"DLEQ");
        let verification = dleq::verify_batchable(
            &ts.proof,
            &mut transcript,
            dleq::VerifyAssignments {
                X: &self.pp.pk.compress(),
                T: &self.public.compress(),
                G: &self.pp.G.compress(),
                W: &ts.signature.compress(),
            },
        );
        verification.map(|_| Token {
            ticket: self.secret.ticket,
            signature: self.secret.blind * ts.signature,
        })
    }

    pub fn unblind(self, ts: TokenSigned) -> Result<Token, zkp::ProofError> {
        self.unsafe_unblind(&ts)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }
}

impl TokenSecret {
    pub fn generate<R>(mut csrng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let mut ticket = [0u8; 32];
        csrng.fill_bytes(&mut ticket);
        let blind = Scalar::random(&mut csrng);
        Self { ticket, blind }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenSigned {
    signature: RistrettoPoint,
    proof: zkp::BatchableProof,
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
        let hashed_ticket = RistrettoPoint::hash_from_bytes::<Sha512>(&secret.ticket);
        let public = secret.blind.invert() * hashed_ticket;
        // XXX we can use lifetimes here
        let pp = *self;
        TokenBlinded { secret, public, pp }
    }

    pub fn to_bytes(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&self)
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
        let signed_token = keypair.sign(&blinded_token.to_bytes());
        assert!(signed_token.is_some());
        let token = blinded_token.unblind(signed_token.unwrap());
        assert!(token.is_ok());
        assert!(keypair.verify(&token.unwrap()).is_ok());
    }
}
