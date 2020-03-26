#[macro_use]
extern crate criterion;
extern crate rand;

extern crate poc;

use criterion::Criterion;
use rand::{thread_rng, RngCore};

use poc::construction1::*;


fn bench_keygen(c: &mut Criterion) {
    c.bench_function("construction1-keygen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });
}



fn bench_tokengen(c: &mut Criterion) {
    c.bench_function("construction1-tokengen", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        b.iter(|| {
            pp.generate_token(&mut csrng);
        });
    });
}



fn bench_sign(c: &mut Criterion) {
    c.bench_function("construction1-sign", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);
        let blinded_token = pp.generate_token(&mut csrng);
        let blind_message = blinded_token.to_bytes();

        b.iter(|| {
            keypair.sign(&blind_message);
        })
    });
}

fn bench_unblind(c: &mut Criterion) {
    c.bench_function("construction1-unblind", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&blinded_token.to_bytes());
        let serialized_signature = signed_token.to_bytes().unwrap();
        b.iter(
            move || {
            let blinded_token : TokenBlinded = unsafe { std::mem::transmute_copy(&blinded_token) };
            let signed_token = TokenSigned::from_bytes(&serialized_signature).unwrap();
            blinded_token.unblind(signed_token);
        });
    });
}



fn bench_redemption(c: &mut Criterion) {
    c.bench_function("construction1-redeem", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);

        let pp = PublicParams::from(&keypair);
        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&blinded_token.to_bytes());
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        let token = token.unwrap();

        b.iter(|| {
            keypair.verify(&token);
        });
    });
}


fn bench_dleq_prove(c: &mut Criterion) {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    c.bench_function("dleq-prove", move |b| {
        let mut csrng = thread_rng();
        let x = Scalar::random(&mut csrng);
        let G = RISTRETTO_BASEPOINT_POINT;
        let T = RistrettoPoint::random(&mut csrng);
        let X = x * G;
        let W = x * G;
        let mut transcript = dleq::Transcript::new(b"dleq-bench");
        b.iter(|| {
            let (proof, _) = dleq::prove_batchable(
                &mut transcript,
                dleq::ProveAssignments { x:&x, X: &X, T: &T, G: &G, W: &W }
            );
        });
    });
}

fn bench_dleq_verify(c: &mut Criterion) {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    c.bench_function("dleq-verify", move |b| {
        let mut csrng = thread_rng();
        let x = Scalar::random(&mut csrng);
        let G = RISTRETTO_BASEPOINT_POINT;
        let T = RistrettoPoint::random(&mut csrng);
        let X = x * G;
        let W = x * G;
        let mut transcript = dleq::Transcript::new(b"dleq-bench");
        let (proof, points) = dleq::prove_batchable(
            &mut transcript,
            dleq::ProveAssignments { x:&x, X: &X, T: &T, G: &G, W: &W }
        );
        b.iter(|| {
            let verification = dleq::verify_batchable(
                &proof,
                &mut transcript,
                dleq::VerifyAssignments {
                    X: &points.X,
                    T: &points.T,
                    G: &points.G,
                    W: &points.W,
                }
            );
        });
    });
}


criterion_group!{
    name = construction1_benchmarks;
    config = Criterion::default();
    targets = bench_keygen, bench_tokengen, bench_sign, bench_unblind, bench_redemption, bench_dleq_prove, bench_dleq_verify,
}
criterion_main!(construction1_benchmarks);
