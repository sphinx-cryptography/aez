use criterion::{
    criterion_group, criterion_main, measurement::CyclesPerByte, BenchmarkId, Criterion, Throughput,
};

use aez::Aez;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("aez");

    const KB: usize = 1024;

    group.bench_function("setup", |b| {
        b.iter(|| Aez::new(&[0u8; 48]))
    });

    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].into_iter() {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            let aez = Aez::new(&[0u8; 48]);
            let mut out = vec![0u8; *size + 16];
            b.iter(|| aez.encrypt(&[0], &[], &buf, &mut out))
        });

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let aez = Aez::new(&[0u8; 48]);
            let mut ct = vec![0u8; *size + 16];
            aez.encrypt(&[0], &[], &buf, &mut ct);
            let mut pt = vec![0u8; *size]; 
            b.iter(|| aez.decrypt(&[0], &[], &ct, &mut pt).unwrap())
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);
criterion_main!(benches);
