#[macro_use]
extern crate criterion;
extern crate poc;

use criterion::Criterion;
use rand::thread_rng;

use poc::pp::dleq;

#[allow(non_snake_case)]
fn bench_dleq_prove(c: &mut Criterion) {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    c.bench_function("dleq-prove", move |b| {
        let mut csrng = thread_rng();
        let x = Scalar::random(&mut csrng);
        let G = RISTRETTO_BASEPOINT_POINT;
        let T = RistrettoPoint::random(&mut csrng);
        let X = x * G;
        let W = x * G;
        let mut transcript = dleq::Transcript::new(b"dleq-bench");
        b.iter(|| {
            let (_proof, _) = dleq::prove_batchable(
                &mut transcript,
                dleq::ProveAssignments {
                    x: &x,
                    X: &X,
                    T: &T,
                    G: &G,
                    W: &W,
                },
            );
        });
    });
}

#[allow(non_snake_case)]
fn bench_dleq_verify(c: &mut Criterion) {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

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
            dleq::ProveAssignments {
                x: &x,
                X: &X,
                T: &T,
                G: &G,
                W: &W,
            },
        );
        b.iter(|| {
            let _verification = dleq::verify_batchable(
                &proof,
                &mut transcript,
                dleq::VerifyAssignments {
                    X: &points.X,
                    T: &points.T,
                    G: &points.G,
                    W: &points.W,
                },
            );
        });
    });
}

criterion_group! {
    name = nizk_benchmarks;
    config = Criterion::default();
    targets = bench_dleq_prove, bench_dleq_verify,
}
criterion_main!(nizk_benchmarks);
