//! Asymmetric mode benchmarks: sealed, signed, and multi-recipient.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use vexil_core::{
    open_multi, open_sealed, open_signed, seal_multi, seal_signed, seal_to, Identity,
    PublicIdentity,
};

fn bench_asymmetric(c: &mut Criterion) {
    let bob = Identity::generate();
    let alice = Identity::generate();
    let msg = vec![0x42u8; 1024];

    let mut group = c.benchmark_group("asymmetric");

    group.bench_function("sealed_encrypt", |b| {
        b.iter(|| seal_to(&bob.public(), &msg).unwrap())
    });
    let sealed = seal_to(&bob.public(), &msg).unwrap();
    group.bench_function("sealed_decrypt", |b| {
        b.iter(|| open_sealed(&bob, &sealed).unwrap())
    });

    group.bench_function("signed_encrypt", |b| {
        b.iter(|| seal_signed(&bob.public(), &alice, &msg).unwrap())
    });
    let signed = seal_signed(&bob.public(), &alice, &msg).unwrap();
    group.bench_function("signed_decrypt", |b| {
        b.iter(|| open_signed(&bob, &signed, Some(&alice.public())).unwrap())
    });

    for n in [1usize, 5, 20] {
        let recips: Vec<PublicIdentity> = (0..n).map(|_| Identity::generate().public()).collect();
        let mut recips_with_bob = recips.clone();
        recips_with_bob.push(bob.public());
        group.bench_with_input(
            BenchmarkId::new("multi_encrypt", n),
            &recips_with_bob,
            |b, r| b.iter(|| seal_multi(r, &msg).unwrap()),
        );
        let multi = seal_multi(&recips_with_bob, &msg).unwrap();
        group.bench_with_input(BenchmarkId::new("multi_decrypt", n), &multi, |b, ct| {
            b.iter(|| open_multi(&bob, ct).unwrap())
        });
    }

    group.finish();
}

criterion_group!(benches, bench_asymmetric);
criterion_main!(benches);
