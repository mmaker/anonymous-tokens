use std::convert::TryInto;

use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE as G, traits::IsIdentity};
use sha2::{Digest, Sha512};

use crate::errors::VerificationError;

#[allow(unused)]
pub struct Token {
    t: [u8; 32],
    challenges: [Scalar; 2],
    responses: [Scalar; 2],
    hs: [RistrettoPoint; 2],
    y: RistrettoPoint,
}
pub struct BlindedCommitmentState {
    clause: usize,
    k_b: Scalar,
    r_1b: Scalar,
    e_1b: Scalar,
    pmb: usize,
}

#[derive(Serialize, Deserialize)]
pub struct Commitment {
    s: [u8; 32],
    y: RistrettoPoint,
    commitments: [[[RistrettoPoint; 2]; 2]; 2],
}

#[derive(Serialize, Deserialize)]
pub struct BlindedResponse {
    clause: usize,
    challenges: [Scalar; 2],
    responses: [Scalar; 2],
}

impl SigningKey {
    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        csrng: &mut R,
        pmb: bool,
    ) -> (BlindedCommitmentState, Commitment) {
        // issuance:
        let mut s = [0u8; 33];
        csrng.fill_bytes(&mut s[..32]);

        s[32] = 0x42;
        let h_0 = RistrettoPoint::hash_from_bytes::<Sha512>(&s);
        s[32] = 0x43;
        let h_1 = RistrettoPoint::hash_from_bytes::<Sha512>(&s);
        // merge them
        let hs = [h_0, h_1];

        let pmb = pmb as usize;
        let y = self.0[pmb] * hs[pmb];

        // fresh elements in issuance
        let clause = csrng.gen::<usize>() & 1;
        let k_b = Scalar::random(csrng);
        let e_1b = Scalar::random(csrng);
        let r_1b = Scalar::random(csrng);

        let mut commitments = [[[RistrettoPoint::default(); 2]; 2]; 2];
        // K_0, C_0
        commitments[clause][pmb] = [&k_b * &G, k_b * hs[pmb]];
        // K_1, C_1
        commitments[clause][1 - pmb] = [
            &(r_1b + e_1b * self.0[1 - pmb]) * &G,
            r_1b * hs[1 - pmb] + e_1b * y,
        ];

        commitments[1 - clause] = [
            [RistrettoPoint::random(csrng), RistrettoPoint::random(csrng)],
            [RistrettoPoint::random(csrng), RistrettoPoint::random(csrng)],
        ];

        // s is an array [u8; 32] so conversion always succeeds.
        let s = s[..32].try_into().unwrap();
        let blinded_commitment = Commitment { s, y, commitments };
        let commitment_state = BlindedCommitmentState {
            clause,
            k_b,
            e_1b,
            r_1b,
            pmb: pmb as usize,
        };

        (commitment_state, blinded_commitment)
    }

    pub fn respond(
        &self,
        commitment_state: BlindedCommitmentState,
        challenges: [Scalar; 2],
    ) -> BlindedResponse {
        self.unsafe_respond(&commitment_state, &challenges)
    }

    pub fn unsafe_respond(
        &self,
        commitment_state: &BlindedCommitmentState,
        challenges: &[Scalar; 2],
    ) -> BlindedResponse {
        let &BlindedCommitmentState {
            clause,
            k_b,
            r_1b,
            e_1b,
            pmb,
        } = commitment_state;

        let e = challenges[clause];
        // the actual challenges returned
        let mut challenges = [Scalar::default(); 2];
        let mut responses = [Scalar::default(); 2];

        challenges[1 - pmb] = e_1b;
        challenges[pmb] = e - e_1b;

        responses[pmb] = k_b - challenges[pmb] * self.0[pmb];
        responses[1 - pmb] = r_1b;

        BlindedResponse {
            clause,
            challenges,
            responses,
        }
    }
}

pub struct UserState {
    alphas: [[Scalar; 2]; 2],
    betas: [[Scalar; 2]; 2],
    t: [u8; 32],
    blind_hs: [RistrettoPoint; 2],
    blind_y: RistrettoPoint,
}

pub struct SigningKey([Scalar; 2]);
pub struct VerifierKey([RistrettoPoint; 2]);

impl From<&SigningKey> for VerifierKey {
    fn from(sk: &SigningKey) -> Self {
        Self([&sk.0[0] * &G, &sk.0[1] * &G])
    }
}

impl SigningKey {
    pub fn new<R: RngCore + CryptoRng>(csrng: &mut R) -> Self {
        Self([Scalar::random(csrng), Scalar::random(csrng)])
    }
}

fn random_oracle(
    xs: &[RistrettoPoint; 2],
    t: &[u8; 32],
    commitments: &[[RistrettoPoint; 2]; 2],
    y: &RistrettoPoint,
    hs: &[RistrettoPoint; 2],
) -> Scalar {
    let h = Sha512::new()
        .chain(b"anonymous-tokens/ristretto25519")
        .chain(xs[0].compress().as_bytes())
        .chain(xs[1].compress().as_bytes())
        .chain(t)
        .chain(commitments[0][0].compress().as_bytes())
        .chain(commitments[0][1].compress().as_bytes())
        .chain(commitments[1][0].compress().as_bytes())
        .chain(commitments[1][1].compress().as_bytes())
        .chain(y.compress().as_bytes())
        .chain(hs[0].compress().as_bytes())
        .chain(hs[1].compress().as_bytes());
    Scalar::from_hash(h)
}
impl VerifierKey {
    pub fn blind<R: RngCore + CryptoRng>(
        &self,
        csrng: &mut R,
        commitment: Commitment,
    ) -> (UserState, [Scalar; 2]) {
        self.unsafe_blind(csrng, &commitment)
    }

    pub fn unsafe_blind<R: RngCore + CryptoRng>(
        &self,
        csrng: &mut R,
        Commitment {
            s: s_,
            y,
            commitments,
        }: &Commitment,
    ) -> (UserState, [Scalar; 2]) {
        let mut s = [0u8; 33];
        let mut t = [0u8; 32];

        s[..32].clone_from_slice(s_);
        csrng.fill_bytes(&mut t);

        s[32] = 0x42;
        let h_0 = RistrettoPoint::hash_from_bytes::<Sha512>(&s);
        s[32] = 0x43;
        let h_1 = RistrettoPoint::hash_from_bytes::<Sha512>(&s);
        // merge them
        let hs = [h_0, h_1];

        let alphas = [
            [Scalar::random(csrng), Scalar::random(csrng)],
            [Scalar::random(csrng), Scalar::random(csrng)],
        ];
        let betas = [
            [Scalar::random(csrng), Scalar::random(csrng)],
            [Scalar::random(csrng), Scalar::random(csrng)],
        ];
        let rho = Scalar::random(csrng);

        let blind_hs = [rho * hs[0], rho * hs[1]];
        let blind_y = rho * y;

        let mut blind_commitments = [[[RistrettoPoint::default(); 2]; 2]; 2];
        let mut challenges = [Scalar::default(); 2];
        for d in 0..2usize {
            for b in 0..2usize {
                blind_commitments[d][b][0] =
                    commitments[d][b][0] + &alphas[d][b] * &G + betas[d][b] * self.0[b];
                blind_commitments[d][b][1] =
                    rho * commitments[d][b][1] + alphas[d][b] * blind_hs[b] + betas[d][b] * blind_y;
            }
            let e = random_oracle(&self.0, &t, &blind_commitments[d], &blind_y, &blind_hs);
            challenges[d] = e - betas[d][0] - betas[d][1];
        }

        let user_state = UserState {
            alphas,
            betas,
            t,
            blind_y,
            blind_hs,
        };
        (user_state, challenges)
    }

    pub fn unblind(
        &self,
        user_state: UserState,
        blinded_response: BlindedResponse,
    ) -> Result<Token, VerificationError> {
        self.unsafe_unblind(&user_state, &blinded_response)
    }

    pub fn unsafe_unblind(
        &self,
        &UserState {
            alphas,
            betas,
            t,
            blind_hs,
            blind_y,
        }: &UserState,
        &BlindedResponse {
            clause,
            challenges: blind_challenges,
            responses: blind_responses,
        }: &BlindedResponse,
    ) -> Result<Token, VerificationError> {
        let token = Token {
            t,
            // unblind the challenges
            challenges: [
                blind_challenges[0] + betas[clause][0],
                blind_challenges[1] + betas[clause][1],
            ],
            // unblind the responses
            responses: [
                blind_responses[0] + alphas[clause][0],
                blind_responses[1] + alphas[clause][1],
            ],
            hs: blind_hs,
            y: blind_y,
        };

        // instead of verifying the transcript, verify the token itself.
        self.verify(&token).map(|()| token)
    }

    pub fn verify(&self, token: &Token) -> Result<(), VerificationError> {
        let Token {
            t,
            hs,
            y,
            challenges,
            responses,
        } = token;
        let commitments = [
            [
                &responses[0] * &G + challenges[0] * self.0[0],
                responses[0] * hs[0] + challenges[0] * y,
            ],
            [
                &responses[1] * &G + challenges[1] * self.0[1],
                responses[1] * hs[1] + challenges[1] * y,
            ],
        ];
        let challenge = random_oracle(&self.0, &t, &commitments, &y, &hs);
        if !hs[0].is_identity()
            && !hs[1].is_identity()
            && challenge == challenges[0] + challenges[1]
        {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

#[test]
fn test_correctness() {
    let csrng = &mut rand::rngs::OsRng;

    let signing_key = SigningKey::new(csrng);
    let verification_key = VerifierKey::from(&signing_key);

    let (srv_state, commitment) = signing_key.commit(csrng, false);
    let (usr_state, challenge) = verification_key.blind(csrng, commitment);
    let response = signing_key.respond(srv_state, challenge);
    let token = verification_key.unblind(usr_state, response);
    assert!(token.is_ok());

    let token = token.unwrap();
    assert!(verification_key.verify(&token).is_ok())
}
