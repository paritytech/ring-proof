use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use ark_ec::AffineRepr;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq};
use ark_std::{test_rng, UniformRand};

use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::booleanity::{BitColumn, Booleanity};
use w3f_plonk_common::gadgets::ec::{AffineColumn, CondAdd};
use w3f_plonk_common::gadgets::inner_prod::InnerProd;
use w3f_plonk_common::gadgets::ProverGadget;
use w3f_plonk_common::test_helpers::{random_bitvec, random_vec};

fn bench_domain_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_creation");
    for log_n in [9, 10, 12, 14] {
        let n = 1usize << log_n;
        group.bench_with_input(BenchmarkId::new("hiding", n), &n, |b, &n| {
            b.iter(|| Domain::<Fq>::new(n, true));
        });
        group.bench_with_input(BenchmarkId::new("non_hiding", n), &n, |b, &n| {
            b.iter(|| Domain::<Fq>::new(n, false));
        });
    }
    group.finish();
}

fn bench_field_column(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("field_column");
    for log_n in [9, 10, 12] {
        let n = 1usize << log_n;
        let domain = Domain::<Fq>::new(n, true);
        let vals: Vec<Fq> = random_vec(domain.capacity - 1, rng);

        group.bench_with_input(
            BenchmarkId::new("private_column", n),
            &(vals.clone(), &domain),
            |b, (vals, domain)| {
                b.iter(|| domain.private_column(vals.clone()));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("public_column", n),
            &(vals.clone(), &domain),
            |b, (vals, domain)| {
                b.iter(|| domain.public_column(vals.clone()));
            },
        );

        let col = domain.private_column(vals);
        group.bench_with_input(BenchmarkId::new("shifted_4x", n), &col, |b, col| {
            b.iter(|| col.shifted_4x());
        });
    }
    group.finish();
}

fn bench_booleanity_gadget(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("booleanity");
    for log_n in [9, 10, 12] {
        let n = 1usize << log_n;
        let domain = Domain::<Fq>::new(n, true);
        let bits = random_bitvec(domain.capacity - 1, 0.5, rng);
        let bit_col = BitColumn::init(bits, &domain);

        group.bench_with_input(
            BenchmarkId::new("constraints", n),
            &bit_col,
            |b, bit_col| {
                let gadget = Booleanity::init(bit_col.clone());
                b.iter(|| gadget.constraints());
            },
        );
    }
    group.finish();
}

fn bench_inner_prod_gadget(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("inner_prod");
    for log_n in [9, 10, 12] {
        let n = 1usize << log_n;
        let domain = Domain::<Fq>::new(n, true);
        let a: Vec<Fq> = random_vec(domain.capacity - 1, rng);
        let b_vals: Vec<Fq> = random_vec(domain.capacity - 1, rng);

        group.bench_with_input(
            BenchmarkId::new("init", n),
            &(a.clone(), b_vals.clone(), &domain),
            |bench, (a, b_vals, domain)| {
                bench.iter(|| {
                    let a_col = domain.private_column(a.clone());
                    let b_col = domain.private_column(b_vals.clone());
                    InnerProd::<Fq>::init(a_col, b_col, domain);
                });
            },
        );

        let a_col = domain.private_column(a);
        let b_col = domain.private_column(b_vals);
        let gadget = InnerProd::<Fq>::init(a_col, b_col, &domain);

        group.bench_with_input(
            BenchmarkId::new("constraints", n),
            &gadget,
            |bench, gadget| {
                bench.iter(|| gadget.constraints());
            },
        );

        let zeta = Fq::rand(rng);
        group.bench_with_input(
            BenchmarkId::new("constraints_linearized", n),
            &(gadget, zeta),
            |bench, (gadget, zeta)| {
                bench.iter(|| gadget.constraints_linearized(zeta));
            },
        );
    }
    group.finish();
}

fn bench_te_cond_add_gadget(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("te_cond_add");
    for log_n in [9, 10, 12] {
        let n = 1usize << log_n;
        let domain = Domain::<Fq>::new(n, true);
        let seed = EdwardsAffine::generator();

        let bitmask = random_bitvec(domain.capacity - 1, 0.5, rng);
        let points = random_vec::<EdwardsAffine, _>(domain.capacity - 1, rng);

        group.bench_with_input(
            BenchmarkId::new("init", n),
            &(bitmask.clone(), points.clone(), &domain),
            |bench, (bitmask, points, domain)| {
                bench.iter(|| {
                    let bitmask_col = BitColumn::init(bitmask.clone(), domain);
                    let points_col = AffineColumn::private_column(points.clone(), domain);
                    CondAdd::init(bitmask_col, points_col, seed, domain);
                });
            },
        );

        let bitmask_col = BitColumn::init(bitmask, &domain);
        let points_col = AffineColumn::private_column(points, &domain);
        let gadget = CondAdd::init(bitmask_col, points_col, seed, &domain);

        group.bench_with_input(
            BenchmarkId::new("constraints", n),
            &gadget,
            |bench, gadget| {
                bench.iter(|| gadget.constraints());
            },
        );

        let zeta = Fq::rand(rng);
        group.bench_with_input(
            BenchmarkId::new("constraints_linearized", n),
            &(gadget, zeta),
            |bench, (gadget, zeta)| {
                bench.iter(|| gadget.constraints_linearized(zeta));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_domain_creation,
    bench_field_column,
    bench_booleanity_gadget,
    bench_inner_prod_gadget,
    bench_te_cond_add_gadget,
);
criterion_main!(benches);
