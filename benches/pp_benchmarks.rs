#[macro_use]
extern crate criterion;

use anonymous_tokens::pp::{KeyPair, PublicParams};
use criterion::Criterion;
use rand::thread_rng;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("PP.KeyGen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });
}

fn bench_tokengen(c: &mut Criterion) {
    c.bench_function("PP.User₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        b.iter(|| {
            pp.generate_token(&mut csrng);
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    c.bench_function("PP.Sign₀", move |b| {
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
    c.bench_function("PP.User₁", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&blinded_token.to_bytes()).unwrap();
        b.iter(move || {
            let _token = blinded_token.unsafe_unblind(&signed_token);
        });
    });
}

fn bench_redemption(c: &mut Criterion) {
    c.bench_function("PP.Verify", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);

        let pp = PublicParams::from(&keypair);
        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&blinded_token.to_bytes()).unwrap();
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        let token = token.unwrap();

        b.iter(|| {
            let _verification = keypair.verify(&token);
        });
    });
}

criterion_group! {
    name = pp_benchmarks;
    config = Criterion::default();
    targets = bench_keygen, bench_tokengen, bench_sign, bench_unblind, bench_redemption,
}
criterion_main!(pp_benchmarks);
