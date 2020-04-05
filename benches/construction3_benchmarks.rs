#[macro_use]
extern crate criterion;
extern crate rand;

extern crate poc;

use criterion::Criterion;
use rand::{thread_rng, RngCore};

use poc::construction3::*;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("construction3-keygen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });
}

fn bench_tokengen(c: &mut Criterion) {
    c.bench_function("construction3-tokengen", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        b.iter(|| {
            pp.generate_token(&mut csrng);
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    c.bench_function("construction3-signing", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);
        let blinded_token = pp.generate_token(&mut csrng);
        let blind_message = blinded_token.to_bytes();

        b.iter(|| {
            keypair.sign(&mut csrng, &blind_message, 0);
        })
    });
}

fn bench_unblind(c: &mut Criterion) {
    c.bench_function("construction3-unblind", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&mut csrng, &blinded_token.to_bytes(), 0);
        let serialized_signature = signed_token.to_bytes().unwrap();
        b.iter(move || {
            let blinded_token: TokenBlinded = unsafe { std::mem::transmute_copy(&blinded_token) };
            let signed_token = TokenSigned::from_bytes(&serialized_signature).unwrap();
            blinded_token.unblind(signed_token);
        });
    });
}

fn bench_redemption(c: &mut Criterion) {
    c.bench_function("construction3-redeem", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);

        let pp = PublicParams::from(&keypair);
        let blinded_token = pp.generate_token(&mut csrng);
        let signed_token = keypair.sign(&mut csrng, &blinded_token.to_bytes(), 0);
        let token = blinded_token.unblind(signed_token);
        assert!(token.is_ok());
        let token = token.unwrap();

        b.iter(|| {
            keypair.verify(&token);
        });
    });
}

criterion_group! {
    name = construction3_benchmarks;
    config = Criterion::default();
    targets = bench_keygen, bench_tokengen, bench_sign, bench_unblind, bench_redemption
}
criterion_main!(construction3_benchmarks);
