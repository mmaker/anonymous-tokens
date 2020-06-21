use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use crate::or_dleq::errors::ProofError;
use crate::zkp::toolbox::TranscriptProtocol;

#[derive(Clone, Serialize, Deserialize)]
pub struct OrDleqProof {
    /// The challenge for the first statement.
    pub(crate) challenges: Vec<Scalar>,
    /// The prover's responses.
    pub(crate) responses: Vec<(Scalar, Scalar)>,
}

pub struct ProveAssignments<'a> {
    pub x: &'a Scalar,
    pub y: &'a Scalar,
    pub b: &'a usize,
    pub X0: &'a RistrettoPoint,
    pub X1: &'a RistrettoPoint,
    pub G: &'a RistrettoPoint,
    pub H: &'a RistrettoPoint,
    pub T: &'a RistrettoPoint,
    pub S: &'a RistrettoPoint,
    pub W: &'a RistrettoPoint,
}

pub struct VerifyAssignments<'a> {
    pub X0: &'a CompressedRistretto,
    pub X1: &'a CompressedRistretto,
    pub G: &'a CompressedRistretto,
    pub H: &'a CompressedRistretto,
    pub T: &'a CompressedRistretto,
    pub S: &'a CompressedRistretto,
    pub W: &'a CompressedRistretto,
}

pub fn prove_compact<'a>(
    transcript: &mut Transcript,
    assignments: ProveAssignments,
) -> OrDleqProof {
    transcript.append_message(b"G", assignments.G.compress().as_bytes());
    transcript.append_message(b"H", assignments.H.compress().as_bytes());
    transcript.append_message(b"T", assignments.T.compress().as_bytes());
    transcript.append_message(b"S", assignments.S.compress().as_bytes());
    transcript.append_message(b"W", assignments.W.compress().as_bytes());
    transcript.append_message(b"X0", assignments.X0.compress().as_bytes());
    transcript.append_message(b"X1", assignments.X1.compress().as_bytes());

    let mut rng = transcript
        .build_rng()
        .rekey_with_witness_bytes(b"witness dlog", &assignments.x.to_bytes())
        .rekey_with_witness_bytes(b"witness bit", &[*assignments.b as u8])
        .finalize(&mut ChaChaRng::from_seed([0; 32]));

    let b = *assignments.b;
    let commitment_secrets = [Scalar::random(&mut rng); 2];
    let simulated_scalars = [Scalar::random(&mut rng); 3];

    let mut commitments = [RistrettoPoint::identity(); 2];
    let mut alt_commitments = [RistrettoPoint::identity(); 2];

    let pk = [*assignments.X0, *assignments.X1];
    let generators = [*assignments.G, *assignments.H];
    let alt_generators = [*assignments.T, *assignments.S];
    let simulated_generators = [pk[1 - b], *assignments.G, *assignments.H];
    let simulated_alt_generators = [*assignments.W, *assignments.T, *assignments.S];

    commitments[b] = RistrettoPoint::multiscalar_mul(&commitment_secrets, &generators);
    commitments[1 - b] = RistrettoPoint::multiscalar_mul(&simulated_scalars, &simulated_generators);
    alt_commitments[b] = RistrettoPoint::multiscalar_mul(&commitment_secrets, &alt_generators);
    alt_commitments[1 - b] =
        RistrettoPoint::multiscalar_mul(&simulated_scalars, &simulated_alt_generators);

    transcript.append_message(b"commitment", commitments[0].compress().as_bytes());
    transcript.append_message(b"commitment", commitments[1].compress().as_bytes());
    transcript.append_message(b"alt_commitment", alt_commitments[0].compress().as_bytes());
    transcript.append_message(b"alt_commitment", alt_commitments[1].compress().as_bytes());

    let mut challenges = vec![Scalar::zero(); 2];
    challenges[1 - b] = simulated_scalars[0];
    challenges[b] = transcript.get_challenge(b"or-chal") - challenges[1 - b];

    let mut responses = vec![(Scalar::zero(), Scalar::zero()); 2];
    responses[1 - b] = (simulated_scalars[1], simulated_scalars[2]);
    responses[b] = (
        commitment_secrets[0] - challenges[b] * assignments.x,
        commitment_secrets[1] - challenges[b] * assignments.y,
    );

    OrDleqProof {
        challenges,
        responses,
    }
}

pub fn verify_compact(
    proof: &OrDleqProof,
    transcript: &mut Transcript,
    assignments: VerifyAssignments,
) -> Result<(), ProofError> {
    transcript.append_message(b"G", assignments.G.as_bytes());
    transcript.append_message(b"H", assignments.H.as_bytes());
    transcript.append_message(b"T", assignments.T.as_bytes());
    transcript.append_message(b"S", assignments.S.as_bytes());
    transcript.append_message(b"W", assignments.W.as_bytes());
    transcript.append_message(b"X0", assignments.X0.as_bytes());
    transcript.append_message(b"X1", assignments.X1.as_bytes());

    let G = assignments.G.decompress().unwrap();
    let H = assignments.H.decompress().unwrap();
    let T = assignments.T.decompress().unwrap();
    let S = assignments.S.decompress().unwrap();
    let W = assignments.W.decompress().unwrap();
    let X0 = assignments.X0.decompress().unwrap();
    let X1 = assignments.X1.decompress().unwrap();

    let commitments: [RistrettoPoint; 2] = [
        RistrettoPoint::multiscalar_mul(
            &[
                proof.challenges[0],
                proof.responses[0].0,
                proof.responses[0].1,
            ],
            &[X0, G, H],
        ),
        RistrettoPoint::multiscalar_mul(
            &[
                proof.challenges[1],
                proof.responses[1].0,
                proof.responses[1].1,
            ],
            &[X1, G, H],
        ),
    ];
    let alt_commitments: [RistrettoPoint; 2] = [
        RistrettoPoint::multiscalar_mul(
            &[
                proof.challenges[0],
                proof.responses[0].0,
                proof.responses[0].1,
            ],
            &[W, T, S],
        ),
        RistrettoPoint::multiscalar_mul(
            &[
                proof.challenges[1],
                proof.responses[1].0,
                proof.responses[1].1,
            ],
            &[W, T, S],
        ),
    ];

    transcript.append_message(b"commitment", commitments[0].compress().as_bytes());
    transcript.append_message(b"commitment", commitments[1].compress().as_bytes());
    transcript.append_message(b"alt_commitment", alt_commitments[0].compress().as_bytes());
    transcript.append_message(b"alt_commitment", alt_commitments[1].compress().as_bytes());

    let expected_challenge = transcript.get_challenge(b"or-chal");
    if expected_challenge == proof.challenges[0] + proof.challenges[1] {
        Ok(())
    } else {
        Err(ProofError::VerificationFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut csrng = rand::rngs::OsRng;
        let mut transcript = Transcript::new(b"test");
        let x = Scalar::random(&mut csrng);
        let y = Scalar::random(&mut csrng);
        let G = RistrettoPoint::random(&mut csrng);
        let H = RistrettoPoint::random(&mut csrng);
        let S = RistrettoPoint::random(&mut csrng);
        let T = RistrettoPoint::random(&mut csrng);
        let W = RistrettoPoint::multiscalar_mul(&[x, y], &[T, S]);
        let X1 = RistrettoPoint::multiscalar_mul(&[x, y], &[G, H]);
        let X0 = RistrettoPoint::random(&mut csrng);
        let b = 1usize;

        let proof = prove_compact(
            &mut transcript,
            ProveAssignments {
                x: &x,
                y: &y,
                b: &b,
                X0: &X0,
                X1: &X1,
                G: &G,
                H: &H,
                T: &T,
                S: &S,
                W: &W,
            },
        );

        let mut transcript = Transcript::new(b"test");
        let verification = verify_compact(
            &proof,
            &mut transcript,
            VerifyAssignments {
                X0: &X0.compress(),
                X1: &X1.compress(),
                G: &G.compress(),
                H: &H.compress(),
                T: &T.compress(),
                S: &S.compress(),
                W: &W.compress(),
            },
        );
        assert!(verification.is_ok());
    }
}
