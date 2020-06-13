#[macro_use]
extern crate criterion;
extern crate rand;

extern crate poc;

use criterion::Criterion;
use rand::thread_rng;

use poc::ppnozk::*;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("ppnozk-keygen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });
}

fn bench_tokengen(c: &mut Criterion) {
    c.bench_function("ppnozk-tokengen", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let ppnozk = PublicParams::from(&keypair);

        b.iter(|| {
            ppnozk.generate_token(&mut csrng);
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    c.bench_function("ppnozk-sign", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let ppnozk = PublicParams::from(&keypair);
        let blinded_token = ppnozk.generate_token(&mut csrng);
        let blind_message = blinded_token.to_bytes();

        b.iter(|| {
            keypair.sign(&blind_message);
        })
    });
}

fn bench_unblind(c: &mut Criterion) {
    c.bench_function("ppnozk-unblind", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let ppnozk = PublicParams::from(&keypair);

        let blinded_token = ppnozk.generate_token(&mut csrng);
        let signed_token = keypair.sign(&blinded_token.to_bytes()).unwrap();
        b.iter(move || {
            let _token = blinded_token.unsafe_unblind(&signed_token);
        });
    });
}

fn bench_redemption(c: &mut Criterion) {
    c.bench_function("ppnozk-redeem", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);

        let ppnozk = PublicParams::from(&keypair);
        let blinded_token = ppnozk.generate_token(&mut csrng);
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
    name = ppnozk_benchmarks;
    config = Criterion::default();
    targets = bench_keygen, bench_tokengen, bench_sign, bench_unblind, bench_redemption,
}
criterion_main!(ppnozk_benchmarks);
