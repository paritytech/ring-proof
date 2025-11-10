#![cfg_attr(not(feature = "std"), no_std)]

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;

use w3f_pcs::pcs::PCS;

use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::Proof;

use w3f_ring_proof::{index, RingProof};
use w3f_ring_proof::{FixedColumnsCommitted, PiopParams, ProverKey, VerifierKey};

/// Polynomial Commitment Schemes.
pub use w3f_pcs::pcs;

use ark_serialize::CanonicalSerialize as _;
use serde_json::json;
use std::fs;

use ark_bls12_381::Bls12_381;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, Fq, Fr};
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use ark_std::{end_timer, start_timer, test_rng, UniformRand};
use w3f_pcs::pcs::kzg::KZG;

use w3f_plonk_common::test_helpers::random_vec;

use w3f_ring_proof::ring::{Ring, RingBuilderKey};
use w3f_ring_proof::ring_prover::RingProver;
use w3f_ring_proof::ring_verifier::RingVerifier;

const DOMAIN_SIZE: usize = 1024;
#[derive(Clone)]
pub struct ArkTranscript(ark_transcript::Transcript);

impl<F: PrimeField, CS: PCS<F>> w3f_plonk_common::transcript::PlonkTranscript<F, CS>
    for ArkTranscript
{
    fn _128_bit_point(&mut self, label: &'static [u8]) -> F {
        self.0.challenge(label).read_reduce()
    }

    fn _add_serializable(&mut self, label: &'static [u8], message: &impl CanonicalSerialize) {
        self.0.label(label);
        self.0.append(message);
    }

    fn to_rng(mut self) -> impl RngCore {
        self.0.challenge(b"transcript_rng")
    }
}

impl ArkTranscript {
    pub fn new(label: &'static [u8]) -> Self {
        Self(ark_transcript::Transcript::new_labeled(label))
    }
}

// helper: serialize any CanonicalSerialize value to hex string
fn to_hex<T: CanonicalSerialize>(v: &T) -> String {
    let mut buf = Vec::new();
    v.serialize_compressed(&mut buf)
        .expect("serialization should succeed");
    buf.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn setup<R: Rng, CS: PCS<Fq>>(
    rng: &mut R,
    domain_size: usize,
) -> (
    CS::Params,
    PiopParams<Fq, BandersnatchConfig>,
    EdwardsAffine,
) {
    let setup_degree = 3 * domain_size;
    let pcs_params = CS::setup(setup_degree, rng);

    let domain = Domain::new(domain_size, true);

    let h = EdwardsAffine::rand(rng);
    let seed = EdwardsAffine::rand(rng);
    let padding = EdwardsAffine::rand(rng);
    let piop_params = PiopParams::setup(domain, h, seed, padding);

    (pcs_params, piop_params, h)
}

fn generate_sample_proof<CS: PCS<Fq>>() -> RingProof<Fq, CS> {
    // Setup RNG and parameters
    let rng = &mut test_rng();

    let (pcs_params, piop_params, h) = setup::<_, CS>(rng, DOMAIN_SIZE);

    let max_keyset_size = piop_params.keyset_part_size;
    let keyset_size: usize = rng.gen_range(0..max_keyset_size);
    let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);
    let k = rng.gen_range(0..keyset_size); // prover's secret index
    let pk = pks[k].clone();

    let (prover_key, verifier_key) = index::<_, CS, _>(&pcs_params, &piop_params, &pks);

    // PROOF generation
    let secret = Fr::rand(rng); // prover's secret scalar
    let result = h.mul(secret) + pk;
    let ring_prover = RingProver::init(
        prover_key,
        piop_params.clone(),
        k,
        ArkTranscript::new(b"w3f-ring-proof-test"),
    );
    let proof = ring_prover.prove(secret);

    ring_prover.prove(secret)
}

fn export_proof_as_json<F: PrimeField, CS: PCS<F>>(proof_to_be_exported: RingProof<F, CS>) {
    let proof = proof_to_be_exported;
    // Build a structured JSON object where each important field is stored as a hex string
    let json_obj = json!({
        "column_commitments": to_hex(&proof.column_commitments),
        "columns_at_zeta": to_hex(&proof.columns_at_zeta),
        "quotient_commitment": to_hex(&proof.quotient_commitment),
        "lin_at_zeta_omega": to_hex(&proof.lin_at_zeta_omega),
        "agg_at_zeta_proof": to_hex(&proof.agg_at_zeta_proof),
        "lin_at_zeta_omega_proof": to_hex(&proof.lin_at_zeta_omega_proof),
    });

    // Write JSON to temp directory to avoid polluting repo root
    let mut path = std::env::temp_dir();
    path.push("ring_proof_structured.json");
    fs::write(
        &path,
        serde_json::to_string_pretty(&json_obj).expect("serialize json"),
    )
    .expect("writing proof json should succeed");

    // Ensure file exists
    assert!(path.exists());
    // Optionally print path for debugging
    println!("Wrote structured proof JSON to {}", path.display());
}

fn main() {
    let proof = generate_sample_proof::<KZG<Bls12_381>>();
    export_proof_as_json(proof);
}
