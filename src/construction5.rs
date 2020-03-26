use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_COMPRESSED};
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use serde::{Serialize, Deserialize};
use sha2::Sha512;
use zkp::Transcript;

use crate::errors::VerificationError;


define_proof! {dlog, "DLOG Knowledge", (x0, y0, x1, y1), (X0, X1), (G, H) :
               X0 = (x0 * G + y0 * H),
               X1 = (x1 * G + y1 * H)
}

type Ticket = [u8; 32];

pub struct KeyPair {
    pub(crate) pp: PublicParams,
    pub(crate) sk: [[Scalar; 2]; 2],
}

#[derive(Clone)]
pub struct PublicParams {
    pk: [RistrettoPoint; 2],
    gen: [RistrettoPoint; 2],
    // XXX. this can be made into one?
    proof: zkp::BatchableProof,
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
        let mut transcript = Transcript::new(b"construction5");
        let (proof, _) = dlog::prove_batchable(
            &mut transcript,
            dlog::ProveAssignments {
                x0: &sk[0][0],
                y0: &sk[0][1],
                x1: &sk[1][0],
                y1: &sk[1][1],
                G:  &gen[0],
                H:  &gen[1],
                X0: &pk[0],
                X1: &pk[1],
            });
        let pp = PublicParams { pk, gen, proof };
        KeyPair { pp, sk }
    }
}


impl<'a> From::<&'a KeyPair> for PublicParams {
    fn from(kp: &'a KeyPair) -> PublicParams {
        kp.pp.clone()
    }
}


impl KeyPair {
    pub fn sign<R>(&self, csrng: &mut R, blind_token: &[[u8; 32]; 2], b: usize) -> TokenSigned
    where R: RngCore + CryptoRng {
        let mut s = [0u8; 32];
        csrng.fill_bytes(&mut s);

        // XXX this should return an option point
        let alt_gens = [
            CompressedRistretto(blind_token[b]).decompress().unwrap(),
            RistrettoPoint::hash_from_bytes::<Sha512>(&s),
        ];
        let signature = RistrettoPoint::multiscalar_mul(&self.sk[b], &alt_gens);
        TokenSigned {s, signature}
    }

    pub fn verify(&self, token: &Token) -> Result<usize, VerificationError> {
        let alt_gens = [
            [RistrettoPoint::hash_from_bytes::<Sha512>(&token.ticket), token.S[0]],
            [RistrettoPoint::hash_from_bytes::<Sha512>(&token.ticket), token.S[1]],
        ];
        let possible_signatures = [
            RistrettoPoint::multiscalar_mul(&self.sk[0], &alt_gens[0]),
            RistrettoPoint::multiscalar_mul(&self.sk[1], &alt_gens[1]),
        ];

        // XXX. make this constant time
        if token.signature[0] == possible_signatures[0] {
            Result::Ok(0)
        } else if token.signature[1] == possible_signatures[1] {
            Result::Ok(1)
        } else {
            Result::Err(VerificationError)
        }
    }
}


struct TokenSecret {
    pub(crate) ticket: Ticket,
    pub(crate) blind: [[Scalar; 2]; 2],
}

pub struct TokenBlinded {
    secret: TokenSecret,
    public: [RistrettoPoint; 2],
    pp: PublicParams,
}

impl TokenBlinded {
    pub fn unblind(self, ts: TokenSigned) ->  Result<Token, zkp::ProofError> {
        let S0 = self.secret.blind[0][0].invert() * RistrettoPoint::hash_from_bytes::<Sha512>(&ts.s) +
                 self.secret.blind[0][1] * self.pp.gen[1];
        let S1 = self.secret.blind[1][0].invert() * RistrettoPoint::hash_from_bytes::<Sha512>(&ts.s) +
                 self.secret.blind[1][1] * self.pp.gen[1];

        let W0 = self.secret.blind[0][0].invert() * ts.signature +
                 self.secret.blind[0][1] * self.pp.pk[0];
        let W1 = self.secret.blind[1][0].invert() * ts.signature +
                 self.secret.blind[1][1] * self.pp.pk[1];

        Ok(Token {
            ticket: self.secret.ticket,
            signature: [W0, W1],
            S: [S0, S1],
        })
    }

    pub fn to_bytes(&self) -> [[u8; 32]; 2] {
        return [self.public[0].compress().to_bytes(),
                self.public[1].compress().to_bytes()]
    }

}
impl TokenSecret {
    pub fn generate<R>(mut csrng: &mut R) -> Self
    where R: RngCore + CryptoRng {
        let mut ticket = [0u8; 32];
        csrng.fill_bytes(&mut ticket);
        // XXX ugly
        let blind = [
            [Scalar::random(&mut csrng), Scalar::random(&mut csrng)],
            [Scalar::random(&mut csrng), Scalar::random(&mut csrng)],
        ];
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
    S: [RistrettoPoint; 2],
    signature: [RistrettoPoint; 2]
}

impl PublicParams {
    pub fn generate_token<R>(&self, mut csrng: &mut R) -> TokenBlinded
    where R: RngCore + CryptoRng {
        let secret = TokenSecret::generate(&mut csrng);
        let T = RistrettoPoint::hash_from_bytes::<Sha512>(&secret.ticket);
        let public = [
            secret.blind[0][0] * (T - secret.blind[0][1]*self.gen[0]),
            secret.blind[1][0] * (T - secret.blind[1][1]*self.gen[0]),
        ];
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
        let signed_token = keypair.sign(&mut csrng, &blinded_token.to_bytes(), 0);
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        assert!(keypair.verify(&token.unwrap()).is_ok());
    }
}
