//! Symmetric (password) encrypt/decrypt throughput per suite and size.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vexil_core::{decrypt_with_password, encrypt_with_password_suite, Suite};

fn bench_symmetric(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric");
    // KDF dominates, so use few samples to keep wall-clock sane.
    group.sample_size(10);

    for &size in &[64usize, 4096, 65536] {
        let data = vec![0xABu8; size];
        for suite in [Suite::XChaPolyArgon, Suite::XAesGcmArgon] {
            group.throughput(Throughput::Bytes(size as u64));
            let label = format!("{:?}/{}B", suite, size);
            group.bench_with_input(BenchmarkId::new("encrypt", &label), &data, |b, d| {
                b.iter(|| encrypt_with_password_suite(suite, b"password", d).unwrap());
            });
            let ct = encrypt_with_password_suite(suite, b"password", &data).unwrap();
            group.bench_with_input(BenchmarkId::new("decrypt", &label), &ct, |b, ct| {
                b.iter(|| decrypt_with_password(b"password", ct).unwrap());
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_symmetric);
criterion_main!(benches);
