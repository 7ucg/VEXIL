//! Codec throughput: Base89, hex, and PEM encode/decode.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vexil_core::Encoding;

fn bench_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec");
    for &size in &[64usize, 1024, 8192] {
        let data = vec![0x9Cu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        for enc in [Encoding::Base89, Encoding::Hex, Encoding::Pem] {
            let label = format!("{}/{}B", enc.name(), size);
            group.bench_with_input(BenchmarkId::new("encode", &label), &data, |b, d| {
                b.iter(|| enc.encode(d))
            });
            let s = enc.encode(&data);
            group.bench_with_input(BenchmarkId::new("decode", &label), &s, |b, s| {
                b.iter(|| enc.decode(s).unwrap())
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
