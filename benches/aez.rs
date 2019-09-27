// benches/aez.rs - aez benchmark
// Copyright (C) 2019  Katzenpost Developers
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;

use aez::Aez;

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("aez");

    const KB: usize = 1024;

    group.bench_function("setup", |b| b.iter(|| Aez::new(&[0u8; 48])));

    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].into_iter() {
        let buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            let aez = Aez::new(&[0u8; 48]);
            let mut out = vec![0u8; *size + 16];
            b.iter(|| aez.encrypt(&[0], None, &buf, &mut out))
        });

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let aez = Aez::new(&[0u8; 48]);
            let mut ct = vec![0u8; *size + 16];
            aez.encrypt(&[0], None, &buf, &mut ct);
            let mut pt = vec![0u8; *size];
            b.iter(|| aez.decrypt(&[0], None, &ct, &mut pt).unwrap())
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
