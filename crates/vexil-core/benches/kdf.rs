//! Argon2id key-derivation cost. This is intentionally slow (memory-hard);
//! the benchmark just measures one derivation.

use criterion::{criterion_group, criterion_main, Criterion};
use vexil_core::kdf::{derive_key, SALT_LEN};

fn bench_kdf(c: &mut Criterion) {
    let salt = [7u8; SALT_LEN];
    let mut group = c.benchmark_group("kdf");
    group.sample_size(10);
    group.bench_function("argon2id_derive", |b| {
        b.iter(|| derive_key(b"correct horse battery staple", &salt).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_kdf);
criterion_main!(benches);
