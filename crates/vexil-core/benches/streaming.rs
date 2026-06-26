//! Streaming (public-key) encrypt/decrypt throughput at real file sizes.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;
use vexil_core::{stream, Identity, Suite};

fn bench_streaming(c: &mut Criterion) {
    let bob = Identity::generate();
    let alice = Identity::generate();
    let mut group = c.benchmark_group("streaming_pk");
    group.sample_size(10);

    for &mib in &[1usize, 10] {
        let size = mib * 1024 * 1024;
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // --- sealed stream ---
        let label = format!("sealed/{}MiB", mib);
        group.bench_with_input(BenchmarkId::new("encrypt", &label), &data, |b, d| {
            b.iter(|| {
                let mut out = Vec::new();
                stream::encrypt_stream_sealed(
                    Suite::XChaPolyArgon,
                    &bob.public(),
                    d,
                    &mut out,
                    &mut OsRng,
                )
                .unwrap();
                out
            });
        });

        let mut sealed_ct = Vec::new();
        stream::encrypt_stream_sealed(
            Suite::XChaPolyArgon,
            &bob.public(),
            &data,
            &mut sealed_ct,
            &mut OsRng,
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", &label), &sealed_ct, |b, ct| {
            b.iter(|| {
                let mut out = Vec::new();
                stream::decrypt_stream_sealed(&bob, &mut ct.as_slice(), &mut out).unwrap();
                out
            });
        });

        // --- signed stream ---
        let label = format!("signed/{}MiB", mib);
        group.bench_with_input(BenchmarkId::new("encrypt", &label), &data, |b, d| {
            b.iter(|| {
                let mut out = Vec::new();
                stream::encrypt_stream_signed(
                    Suite::XChaPolyArgon,
                    &bob.public(),
                    &alice,
                    d,
                    &mut out,
                    &mut OsRng,
                )
                .unwrap();
                out
            });
        });

        // --- multi-recipient stream (3 recipients) ---
        let recipients = vec![bob.public(), alice.public(), Identity::generate().public()];
        let label = format!("multi3/{}MiB", mib);
        group.bench_with_input(BenchmarkId::new("encrypt", &label), &data, |b, d| {
            b.iter(|| {
                let mut out = Vec::new();
                stream::encrypt_stream_multi(
                    Suite::XChaPolyArgon,
                    &recipients,
                    d,
                    &mut out,
                    &mut OsRng,
                )
                .unwrap();
                out
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_streaming);
criterion_main!(benches);
