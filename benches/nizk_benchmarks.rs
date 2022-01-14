#[macro_use]
extern crate criterion;
extern crate poc;

use criterion::Criterion;
use rand::thread_rng;

use poc::or_dleq;
use poc::pp::dleq;

#[allow(non_snake_case)]
fn bench_dleq_prove(c: &mut Criterion) {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    c.bench_function("DLEQ.Prove", move |b| {
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

    c.bench_function("DLEQ.Verify", move |b| {
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

#[allow(non_snake_case)]
fn bench_ordleq_prove(c: &mut Criterion) {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::MultiscalarMul;
    use merlin::Transcript;

    c.bench_function("ORDLEQ.Prove", move |b| {
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
        let bit = 1usize;

        b.iter(|| {
            let _proof = or_dleq::prove_compact(
                &mut transcript,
                or_dleq::ProveAssignments {
                    x: &x,
                    y: &y,
                    b: &bit,
                    X0: &X0,
                    X1: &X1,
                    G: &G,
                    H: &H,
                    T: &T,
                    S: &S,
                    W: &W,
                },
            );
        });
    });
}

#[allow(non_snake_case)]
fn bench_ordleq_verify(c: &mut Criterion) {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::MultiscalarMul;
    use merlin::Transcript;

    c.bench_function("ORDLEQ.Verify", move |b| {
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
        let bit = 1usize;

        let proof = or_dleq::prove_compact(
            &mut transcript,
            or_dleq::ProveAssignments {
                x: &x,
                y: &y,
                b: &bit,
                X0: &X0,
                X1: &X1,
                G: &G,
                H: &H,
                T: &T,
                S: &S,
                W: &W,
            },
        );

        b.iter(|| {
            let _verification = or_dleq::verify_compact(
                &proof,
                &mut transcript,
                or_dleq::VerifyAssignments {
                    X0: &X0.compress(),
                    X1: &X1.compress(),
                    G: &G.compress(),
                    H: &H.compress(),
                    T: &T.compress(),
                    S: &S.compress(),
                    W: &W.compress(),
                },
            );
        });
    });
}

criterion_group! {
    name = nizk_benchmarks;
    config = Criterion::default();
    targets = bench_dleq_prove, bench_dleq_verify, bench_ordleq_prove, bench_ordleq_verify
}
criterion_main!(nizk_benchmarks);
