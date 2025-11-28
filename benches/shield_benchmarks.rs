//! Benchmarks for Trinity Shield
//! 
//! Run with: cargo bench --features std

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn crypto_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto");
    
    // SHA-256
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("sha256_1kb", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            trinity_shield::crypto::sha256(black_box(&data))
        });
    });
    
    // AES-256-GCM
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("aes256_gcm_encrypt_1kb", |b| {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let data = vec![0u8; 1024];
        b.iter(|| {
            trinity_shield::crypto::aes256_gcm_encrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&data),
                black_box(b""),
            )
        });
    });
    
    group.finish();
}

fn shield_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("shield");
    
    // Rate limiter
    group.bench_function("rate_limiter_check", |b| {
        let limiter = trinity_shield::perimeter::RateLimiter::new(1000, 2000);
        b.iter(|| {
            limiter.check(black_box("192.168.1.1"))
        });
    });
    
    // IP filter
    group.bench_function("ip_filter_check", |b| {
        let filter = trinity_shield::perimeter::IpFilter::new(
            vec!["10.0.0.0/8".into()],
            vec!["192.168.1.100".into()],
            false,
            vec![],
        );
        b.iter(|| {
            filter.check(black_box("10.0.0.1"))
        });
    });
    
    group.finish();
}

criterion_group!(benches, crypto_benchmarks, shield_benchmarks);
criterion_main!(benches);
