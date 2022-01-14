#[macro_use]
extern crate criterion;
extern crate rand;

extern crate poc;

use criterion::Criterion;
use rand::thread_rng;

use poc::pmbt::*;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("PMBT.KeyGen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });
}

fn bench_tokengen(c: &mut Criterion) {
    c.bench_function("PMBT.User₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pmbtnozk = PublicParams::from(&keypair);

        b.iter(|| {
            pmbtnozk.generate_token(&mut csrng);
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    c.bench_function("PMBT.Sign", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pmbtnozk = PublicParams::from(&keypair);
        let blinded_token = pmbtnozk.generate_token(&mut csrng);
        let blind_message = blinded_token.to_bytes();

        b.iter(|| {
            keypair.sign(&mut csrng, &blind_message, 0);
        })
    });
}

fn bench_unblind(c: &mut Criterion) {
    c.bench_function("PMBT.User₁", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pmbtnozk = PublicParams::from(&keypair);

        let blinded_token = pmbtnozk.generate_token(&mut csrng);
        let signed_token = keypair
            .sign(&mut csrng, &blinded_token.to_bytes(), 0)
            .unwrap();
        b.iter(move || {
            let _token = blinded_token.unsafe_unblind(&signed_token);
        });
    });
}

fn bench_redemption(c: &mut Criterion) {
    c.bench_function("PMBT.Verify", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);

        let pmbtnozk = PublicParams::from(&keypair);
        let blinded_token = pmbtnozk.generate_token(&mut csrng);
        let signed_token = keypair
            .sign(&mut csrng, &blinded_token.to_bytes(), 0)
            .unwrap();
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        let token = token.unwrap();

        b.iter(|| {
            let _verification = keypair.verify(&token);
        });
    });
}

criterion_group! {
    name = pmbtnozk_benchmarks;
    config = Criterion::default();
    targets = bench_keygen, bench_tokengen, bench_sign, bench_unblind, bench_redemption,
}
criterion_main!(pmbtnozk_benchmarks);
