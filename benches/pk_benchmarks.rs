#[macro_use]
extern crate criterion;

use anonymous_tokens::pk::blor::{SigningKey, VerifierKey};
use criterion::Criterion;
use rand::Rng;

#[allow(non_snake_case)]
fn bench_blor(c: &mut Criterion) {
    c.bench_function("BLOR.KeyGen", move |b| {
        let mut csrng = rand::rngs::OsRng;
        b.iter(|| SigningKey::new(&mut csrng));
    });

    c.bench_function("BLOR.commit", move |b| {
        let mut csrng = rand::rngs::OsRng;
        let sk = SigningKey::new(&mut csrng);
        b.iter(|| sk.commit(&mut csrng, false));
    });

    c.bench_function("BLOR.blind", move |b| {
        let mut csrng = rand::rngs::OsRng;
        let sk = SigningKey::new(&mut csrng);
        let vk = VerifierKey::from(&sk);
        let pmb = csrng.gen::<bool>();
        let (_, commitment) = sk.commit(&mut csrng, pmb);
        b.iter(|| vk.unsafe_blind(&mut csrng, &commitment));
    });

    c.bench_function("BLOR.response", move |b| {
        let mut csrng = rand::rngs::OsRng;
        let sk = SigningKey::new(&mut csrng);
        let vk = VerifierKey::from(&sk);
        let pmb = csrng.gen::<bool>();
        let (commitment_state, commitment) = sk.commit(&mut csrng, pmb);
        let (_, challenges) = vk.blind(&mut csrng, commitment);
        b.iter(|| sk.unsafe_respond(&commitment_state, &challenges));
    });

    c.bench_function("BLOR.unblind", move |b| {
        let mut csrng = rand::rngs::OsRng;
        let sk = SigningKey::new(&mut csrng);
        let vk = VerifierKey::from(&sk);
        let pmb = csrng.gen::<bool>();
        let (commitment_state, commitment) = sk.commit(&mut csrng, pmb);
        let (user_state, challenges) = vk.blind(&mut csrng, commitment);
        let blinded_response = sk.unsafe_respond(&commitment_state, &challenges);
        b.iter(|| vk.unsafe_unblind(&user_state, &blinded_response));
    });

    c.bench_function("BLOR.verify", move |b| {
        let mut csrng = rand::rngs::OsRng;
        let sk = SigningKey::new(&mut csrng);
        let vk = VerifierKey::from(&sk);
        let pmb = csrng.gen::<bool>();
        let (commitment_state, commitment) = sk.commit(&mut csrng, pmb);
        let (user_state, challenges) = vk.blind(&mut csrng, commitment);
        let blinded_response = sk.unsafe_respond(&commitment_state, &challenges);
        let token = vk.unblind(user_state, blinded_response).unwrap();
        b.iter(|| vk.verify(&token));
    });


    c.bench_function("BLOR.read", move |b| {
        let mut csrng = rand::rngs::OsRng;
        let sk = SigningKey::new(&mut csrng);
        let vk = VerifierKey::from(&sk);
        let pmb = csrng.gen::<bool>();
        let (commitment_state, commitment) = sk.commit(&mut csrng, pmb);
        let (user_state, challenges) = vk.blind(&mut csrng, commitment);
        let blinded_response = sk.unsafe_respond(&commitment_state, &challenges);
        let token = vk.unblind(user_state, blinded_response).unwrap();
        b.iter(|| sk.read(&token));
    });
}

criterion_group! {
    name = bsms_benchmarks;
    config = Criterion::default();
    targets = bench_blor
}
criterion_main!(bsms_benchmarks);
