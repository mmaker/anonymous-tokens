#[macro_use]
extern crate criterion;
extern crate rand;

use criterion::Criterion;
use rand::thread_rng;

fn bench_pmbt(c: &mut Criterion) {
    use anonymous_tokens::sk::pmbt::{KeyPair, PublicParams};

    c.bench_function("PMBT.KeyGen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });

    c.bench_function("PMBT.User₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pmbtnozk = PublicParams::from(&keypair);

        b.iter(|| {
            pmbtnozk.generate_token(&mut csrng);
        });
    });

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

fn bench_pmbtnozk(c: &mut Criterion) {
    use anonymous_tokens::sk::pmbtnozk::{KeyPair, PublicParams};

    c.bench_function("PMBTB.KeyGen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });

    c.bench_function("PMBTB.User₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pmbtnozk = PublicParams::from(&keypair);

        b.iter(|| {
            pmbtnozk.generate_token(&mut csrng);
        });
    });

    c.bench_function("PMBTB.Sign₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pmbtnozk = PublicParams::from(&keypair);
        let blinded_token = pmbtnozk.generate_token(&mut csrng);
        let blind_message = blinded_token.to_bytes();

        b.iter(|| {
            keypair.sign(&mut csrng, &blind_message, 0);
        })
    });

    c.bench_function("PMBTB.User₁", move |b| {
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

    c.bench_function("PMBTB.Verify", move |b| {
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

fn bench_ppnozk(c: &mut Criterion) {
    use anonymous_tokens::sk::ppnozk::{KeyPair, PublicParams};

    c.bench_function("PPB.KeyGen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });

    c.bench_function("PPB.User₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let ppnozk = PublicParams::from(&keypair);

        b.iter(|| {
            ppnozk.generate_token(&mut csrng);
        });
    });

    c.bench_function("PPB.Sign₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let ppnozk = PublicParams::from(&keypair);
        let blinded_token = ppnozk.generate_token(&mut csrng);
        let blind_message = blinded_token.to_bytes();

        b.iter(|| {
            keypair.sign(&blind_message);
        })
    });

    c.bench_function("PPB.User₁", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let ppnozk = PublicParams::from(&keypair);

        let blinded_token = ppnozk.generate_token(&mut csrng);
        let signed_token = keypair.sign(&blinded_token.to_bytes()).unwrap();
        b.iter(move || {
            let _token = blinded_token.unsafe_unblind(&signed_token);
        });
    });

    c.bench_function("PPB.Verify", move |b| {
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

fn bench_pp(c: &mut Criterion) {
    use anonymous_tokens::sk::pp::{KeyPair, PublicParams};

    c.bench_function("PP.KeyGen", move |b| {
        let mut csrng = thread_rng();
        b.iter(|| {
            KeyPair::generate(&mut csrng);
        });
    });

    c.bench_function("PP.User₀", move |b| {
        let mut csrng = thread_rng();
        let keypair = KeyPair::generate(&mut csrng);
        let pp = PublicParams::from(&keypair);

        b.iter(|| {
            pp.generate_token(&mut csrng);
        });
    });

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
    name = pmbtnozk_benchmarks;
    config = Criterion::default();
    targets = bench_pmbt, bench_pmbtnozk, bench_ppnozk, bench_pp
}
criterion_main!(pmbtnozk_benchmarks);
