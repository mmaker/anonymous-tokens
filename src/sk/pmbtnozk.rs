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

define_proof! {
    osdlog, "DLOG Proof", (x0, y0, x1, y1), (X0, X1), (G, H) :
    X0 = (x0 * G + y0 * H),
    X1 = (x1 * G + y1 * H)
}

pub struct KeyPair {
    pub(crate) pp: PublicParams,
    pub(crate) sk: [[Scalar; 2]; 2],
}

#[allow(unused)] // this disables the warning on `proof` being unused.
#[derive(Clone)]
pub struct PublicParams {
    pub(crate) pk: [RistrettoPoint; 2],
    pub(crate) gen: [RistrettoPoint; 2],
    pub(crate) proof: zkp::CompactProof,
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

        let mut transcript = Transcript::new(b"DLOG");
        let (proof, _) = osdlog::prove_compact(
            &mut transcript,
            osdlog::ProveAssignments {
                x0: &sk[0][0],
                y0: &sk[0][1],
                x1: &sk[1][1],
                y1: &sk[1][1],
                X0: &pk[0],
                X1: &pk[1],
                G: &gen[0],
                H: &gen[1],
            },
        );

        let pp = PublicParams { pk, gen, proof };
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
            [
                CompressedRistretto::from_slice(&blind_token[..32]).decompress()?,
                RistrettoPoint::hash_from_bytes::<Sha512>(&s),
            ],
            [
                CompressedRistretto::from_slice(&blind_token[32..]).decompress()?,
                RistrettoPoint::hash_from_bytes::<Sha512>(&s),
            ],
        ];
        let signature = RistrettoPoint::multiscalar_mul(&self.sk[b], &alt_gens[b]);

        Some(TokenSigned { s, signature })
    }

    pub fn verify(&self, token: &Token) -> Result<usize, VerificationError> {
        let alt_gens = [
            [
                RistrettoPoint::hash_from_bytes::<Sha512>(&token.ticket),
                token.S[0],
            ],
            [
                RistrettoPoint::hash_from_bytes::<Sha512>(&token.ticket),
                token.S[1],
            ],
        ];

        let possible_signatures = (
            RistrettoPoint::multiscalar_mul(&self.sk[0], &alt_gens[0]),
            RistrettoPoint::multiscalar_mul(&self.sk[1], &alt_gens[1]),
        );

        if token.signature[0] == possible_signatures.0 {
            Result::Ok(0)
        } else if token.signature[1] == possible_signatures.1 {
            Result::Ok(1)
        } else {
            Result::Err(VerificationError)
        }
    }
}

struct TokenSecret {
    pub(crate) ticket: Ticket,
    pub(crate) additive_blind: [Scalar; 2],
    pub(crate) multiplicative_blind: [Scalar; 2],
}

pub struct TokenBlinded {
    secret: TokenSecret,
    public: [RistrettoPoint; 2],
    pp: PublicParams,
}

impl TokenBlinded {
    pub fn unsafe_unblind(&self, ts: &TokenSigned) -> Result<Token, zkp::ProofError> {
        let ticket = self.secret.ticket;
        // XXX: fix generation of S, it should integrate T'
        let S = [
            self.secret.multiplicative_blind[0] * RistrettoPoint::hash_from_bytes::<Sha512>(&ts.s)
                + self.secret.additive_blind[0] * self.pp.gen[1],
            self.secret.multiplicative_blind[1] * RistrettoPoint::hash_from_bytes::<Sha512>(&ts.s)
                + self.secret.additive_blind[1] * self.pp.gen[1],
        ];
        let signature = [
            self.secret.multiplicative_blind[0] * ts.signature
                + self.secret.additive_blind[0] * self.pp.pk[0],
            self.secret.multiplicative_blind[1] * ts.signature
                + self.secret.additive_blind[1] * self.pp.pk[1],
        ];

        Ok(Token {
            ticket,
            S,
            signature,
        })
    }

    pub fn unblind(self, ts: TokenSigned) -> Result<Token, zkp::ProofError> {
        self.unsafe_unblind(&ts)
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        // XXX Fix this
        let fst = self.public[0].compress().to_bytes();
        let snd = self.public[1].compress().to_bytes();
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
        let additive_blind = [Scalar::random(&mut csrng), Scalar::random(&mut csrng)];
        let multiplicative_blind = [Scalar::random(&mut csrng), Scalar::random(&mut csrng)];
        Self {
            ticket,
            additive_blind,
            multiplicative_blind,
        }
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
        bincode::deserialize(s)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    ticket: Ticket,
    S: [RistrettoPoint; 2],
    signature: [RistrettoPoint; 2],
}

impl PublicParams {
    pub fn generate_token<R>(&self, mut csrng: &mut R) -> TokenBlinded
    where
        R: RngCore + CryptoRng,
    {
        let secret = TokenSecret::generate(&mut csrng);
        let hashed_ticket = RistrettoPoint::hash_from_bytes::<Sha512>(&secret.ticket);
        let public = [
            secret.multiplicative_blind[0].invert()
                * (hashed_ticket - secret.additive_blind[0] * self.gen[0]),
            secret.multiplicative_blind[1].invert()
                * (hashed_ticket - secret.additive_blind[1] * self.gen[0]),
        ];
        // XXX we can use lifetimes here
        let pp = self.clone();
        TokenBlinded { secret, public, pp }
    }
}

#[test]
fn test_correctness() {
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
