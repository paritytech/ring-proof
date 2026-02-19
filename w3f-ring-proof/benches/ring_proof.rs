use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use ark_bls12_381::Bls12_381;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, Fq, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use ark_std::{test_rng, UniformRand};
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::PCS;

use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::test_helpers::random_vec;
use w3f_ring_proof::ring_prover::RingProver;
use w3f_ring_proof::ring_verifier::RingVerifier;
use w3f_ring_proof::{index, ArkTranscript, PiopParams, RingProof};

type CS = KZG<Bls12_381>;

fn setup(
    rng: &mut impl Rng,
    domain_size: usize,
) -> (<CS as PCS<Fq>>::Params, PiopParams<Fq, BandersnatchConfig>) {
    let setup_degree = 3 * domain_size;
    let pcs_params = CS::setup(setup_degree, rng);
    let domain = Domain::new(domain_size, true);
    let h = EdwardsAffine::rand(rng);
    let seed = EdwardsAffine::rand(rng);
    let padding = EdwardsAffine::rand(rng);
    let piop_params = PiopParams::setup(domain, h, seed, padding);
    (pcs_params, piop_params)
}

fn make_transcript() -> ArkTranscript {
    ArkTranscript::new(b"w3f-ring-proof-bench")
}

/// Get the Pedersen blinding base H from the PIOP params (first element of the power-of-2 multiples).
fn get_h(piop_params: &PiopParams<Fq, BandersnatchConfig>) -> EdwardsAffine {
    piop_params.power_of_2_multiples_of_h()[0]
}

/// Generate a proof and its corresponding blinded public key.
fn generate_proof(
    piop_params: &PiopParams<Fq, BandersnatchConfig>,
    pcs_params: &<CS as PCS<Fq>>::Params,
    pks: &[EdwardsAffine],
    rng: &mut impl Rng,
) -> (EdwardsAffine, RingProof<Fq, CS>) {
    let h = get_h(piop_params);
    let prover_idx = rng.gen_range(0..pks.len());
    let (prover_key, _) = index::<_, CS, _>(pcs_params, piop_params, pks);
    let prover = RingProver::init(prover_key, piop_params.clone(), prover_idx, make_transcript());
    let blinding_factor = Fr::rand(rng);
    let blinded_pk = (pks[prover_idx] + h.mul(blinding_factor)).into_affine();
    let proof = prover.prove(blinding_factor);
    (blinded_pk, proof)
}

fn bench_setup(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/setup");
    group.sample_size(10);

    for log_n in [9, 10] {
        let n = 1usize << log_n;
        group.bench_with_input(BenchmarkId::new("pcs_and_piop", n), &n, |b, &n| {
            b.iter(|| setup(rng, n));
        });
    }
    group.finish();
}

fn bench_index(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/index");
    group.sample_size(10);

    for log_n in [9, 10] {
        let n = 1usize << log_n;
        let (pcs_params, piop_params) = setup(rng, n);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);

        group.bench_with_input(BenchmarkId::new("full_keyset", n), &n, |b, _| {
            b.iter(|| index::<_, CS, _>(&pcs_params, &piop_params, &pks));
        });
    }
    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/prove");
    group.sample_size(10);

    for log_n in [9, 10] {
        let n = 1usize << log_n;
        let (pcs_params, piop_params) = setup(rng, n);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);
        let (prover_key, _) = index::<_, CS, _>(&pcs_params, &piop_params, &pks);

        let prover_idx = rng.gen_range(0..keyset_size);
        let prover =
            RingProver::init(prover_key, piop_params.clone(), prover_idx, make_transcript());

        group.bench_with_input(BenchmarkId::new("single", n), &n, |b, _| {
            let blinding_factor = Fr::rand(rng);
            b.iter(|| prover.prove(blinding_factor));
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/verify");
    group.sample_size(10);

    for log_n in [9, 10] {
        let n = 1usize << log_n;
        let (pcs_params, piop_params) = setup(rng, n);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);

        let (blinded_pk, proof) = generate_proof(&piop_params, &pcs_params, &pks, rng);
        let (_, verifier_key) = index::<_, CS, _>(&pcs_params, &piop_params, &pks);
        let verifier = RingVerifier::init(verifier_key, piop_params, make_transcript());

        group.bench_with_input(BenchmarkId::new("single", n), &n, |b, _| {
            b.iter(|| verifier.verify(proof.clone(), blinded_pk));
        });
    }
    group.finish();
}

fn bench_verify_batch_sequential(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/verify_batch_sequential");
    group.sample_size(10);

    let log_n = 10;
    let n = 1usize << log_n;
    let (pcs_params, piop_params) = setup(rng, n);
    let keyset_size = piop_params.keyset_part_size;
    let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);

    // Pre-generate proofs for the largest batch.
    let max_batch = 32;
    let claims: Vec<(EdwardsAffine, RingProof<Fq, CS>)> = (0..max_batch)
        .map(|_| generate_proof(&piop_params, &pcs_params, &pks, rng))
        .collect();

    let (_, verifier_key) = index::<_, CS, _>(&pcs_params, &piop_params, &pks);
    let verifier = RingVerifier::init(verifier_key, piop_params, make_transcript());

    for batch_size in [1, 4, 16, 32] {
        let (results, proofs): (Vec<_>, Vec<_>) = claims[..batch_size].iter().cloned().unzip();

        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| verifier.verify_batch(proofs.clone(), results.clone()));
            },
        );
    }
    group.finish();
}

fn bench_verify_batch_kzg(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/verify_batch_kzg");
    group.sample_size(10);

    let log_n = 10;
    let n = 1usize << log_n;
    let (pcs_params, piop_params) = setup(rng, n);
    let keyset_size = piop_params.keyset_part_size;
    let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);

    let max_batch = 32;
    let claims: Vec<(EdwardsAffine, RingProof<Fq, CS>)> = (0..max_batch)
        .map(|_| generate_proof(&piop_params, &pcs_params, &pks, rng))
        .collect();

    for batch_size in [1, 4, 16, 32] {
        let (results, proofs): (Vec<_>, Vec<_>) = claims[..batch_size].iter().cloned().unzip();

        group.bench_with_input(
            BenchmarkId::new("kzg_accumulator", batch_size),
            &batch_size,
            |b, _| {
                // Recreate verifier each iteration since verify_batch_kzg consumes self.
                b.iter_batched(
                    || {
                        let (_, vk) = index::<_, CS, _>(&pcs_params, &piop_params, &pks);
                        let verifier =
                            RingVerifier::init(vk, piop_params.clone(), make_transcript());
                        (verifier, proofs.clone(), results.clone())
                    },
                    |(verifier, proofs, results)| verifier.verify_batch_kzg(proofs, results),
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_proof_size(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("ring_proof/serialization");
    group.sample_size(10);

    let n = 1usize << 10;
    let (pcs_params, piop_params) = setup(rng, n);
    let keyset_size = piop_params.keyset_part_size;
    let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);

    let (_, proof) = generate_proof(&piop_params, &pcs_params, &pks, rng);

    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    let proof_size = buf.len();

    group.bench_function(
        BenchmarkId::new("serialize_compressed", format!("{proof_size}_bytes")),
        |b| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(proof_size);
                proof.serialize_compressed(&mut buf).unwrap();
                buf
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_setup,
    bench_index,
    bench_prove,
    bench_verify,
    bench_verify_batch_sequential,
    bench_verify_batch_kzg,
    bench_proof_size,
);
criterion_main!(benches);
