#![cfg_attr(not(feature = "std"), no_std)]

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use w3f_pcs::pcs::PCS;

pub use piop::index;
pub use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::Proof;

pub use crate::piop::{params::PiopParams, FixedColumnsCommitted, ProverKey, VerifierKey};
use crate::piop::{RingCommitments, RingEvaluations};

mod piop;
pub mod ring;
pub mod ring_prover;
pub mod ring_verifier;

pub type RingProof<F, CS> = Proof<F, CS, RingCommitments<F, <CS as PCS<F>>::C>, RingEvaluations<F>>;

/// Polynomial Commitment Schemes.
pub use w3f_pcs::pcs;

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

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, Fq, Fr};
    use ark_std::ops::Mul;
    use ark_std::rand::Rng;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use w3f_pcs::pcs::kzg::KZG;

    use w3f_plonk_common::test_helpers::random_vec;

    use crate::piop::FixedColumnsCommitted;
    use crate::ring::{Ring, RingBuilderKey};
    use crate::ring_prover::RingProver;
    use crate::ring_verifier::RingVerifier;

    use super::*;

    fn _test_ring_proof<CS: PCS<Fq>>(
        domain_size: usize,
        batch_size: usize,
    ) -> (
        RingVerifier<Fq, CS, BandersnatchConfig>,
        Vec<(EdwardsAffine, RingProof<Fq, CS>)>,
    ) {
        let rng = &mut test_rng();

        let (pcs_params, piop_params) = setup::<_, CS>(rng, domain_size);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);
        let (prover_key, verifier_key) = index::<_, CS, _>(&pcs_params, &piop_params, &pks);

        let t_prove = start_timer!(|| "Prove");
        let claims: Vec<(EdwardsAffine, RingProof<Fq, CS>)> = (0..batch_size)
            .map(|_| {
                let prover_idx = rng.gen_range(0..keyset_size);
                let prover = RingProver::init(
                    prover_key.clone(),
                    piop_params.clone(),
                    prover_idx,
                    ArkTranscript::new(b"w3f-ring-proof-test"),
                );
                let prover_pk = pks[prover_idx].clone();
                let blinding_factor = Fr::rand(rng);
                let blinded_pk = prover_pk + piop_params.h.mul(blinding_factor);
                let blinded_pk = blinded_pk.into_affine();
                let proof = prover.prove(blinding_factor);
                (blinded_pk, proof)
            })
            .collect();
        end_timer!(t_prove);

        let ring_verifier = RingVerifier::init(
            verifier_key,
            piop_params,
            ArkTranscript::new(b"w3f-ring-proof-test"),
        );
        let t_verify = start_timer!(|| "Verify");
        let (blinded_pks, proofs) = claims.iter().cloned().unzip();
        assert!(ring_verifier.verify_batch(proofs, blinded_pks));
        end_timer!(t_verify);
        (ring_verifier, claims)
    }

    #[test]
    fn test_lagrangian_commitment() {
        let rng = &mut test_rng();

        let domain_size = 2usize.pow(9);

        let (pcs_params, piop_params) = setup::<_, KZG<Bls12_381>>(rng, domain_size);
        let ring_builder_key = RingBuilderKey::from_srs(&pcs_params, domain_size);

        let max_keyset_size = piop_params.keyset_part_size;
        let keyset_size: usize = rng.gen_range(0..max_keyset_size);
        let pks = random_vec::<EdwardsAffine, _>(keyset_size, rng);

        let (_, verifier_key) = index::<_, KZG<Bls12_381>, _>(&pcs_params, &piop_params, &pks);

        let ring = Ring::<_, Bls12_381, _>::with_keys(&piop_params, &pks, &ring_builder_key);

        let fixed_columns_committed = FixedColumnsCommitted::from_ring(&ring);
        assert_eq!(
            fixed_columns_committed,
            verifier_key.fixed_columns_committed
        );
    }

    fn setup<R: Rng, CS: PCS<Fq>>(
        rng: &mut R,
        domain_size: usize,
    ) -> (CS::Params, PiopParams<Fq, BandersnatchConfig>) {
        let setup_degree = 3 * domain_size;
        let pcs_params = CS::setup(setup_degree, rng);

        let domain = Domain::new(domain_size, true);
        let h = EdwardsAffine::rand(rng);
        let seed = EdwardsAffine::rand(rng);
        let padding = EdwardsAffine::rand(rng);
        let piop_params = PiopParams::setup(domain, h, seed, padding);

        (pcs_params, piop_params)
    }

    // cargo test test_ring_proof_kzg --release --features="print-trace" -- --show-output
    //
    // Batch vs sequential verification times (ms):
    //
    // | proofs | batch  | sequential | speedup |
    // |--------|--------|------------|---------|
    // | 1      | 2.790  | 3.032      | 1.09x   |
    // | 2      | 3.218  | 6.425      | 2.00x   |
    // | 4      | 5.122  | 11.968     | 2.34x   |
    // | 8      | 6.487  | 23.922     | 3.69x   |
    // | 16     | 10.002 | 47.773     | 4.78x   |
    // | 32     | 16.601 | 95.570     | 5.76x   |
    // | 64     | 29.484 | 210.959    | 7.15x   |
    // | 128    | 52.170 | 422.217    | 8.09x   |
    // | 256    | 85.164 | 762.874    | 8.96x   |
    //
    // Sequential verification scales linearly with proof count. Batch verification
    // scales sub-linearly.
    #[test]
    fn test_ring_proof_kzg() {
        let batch_size: usize = 16;
        let (verifier, claims) = _test_ring_proof::<KZG<Bls12_381>>(2usize.pow(10), batch_size);
        let t_verify_batch = start_timer!(|| format!("Verify Batch KZG (batch={batch_size})"));
        let (blinded_pks, proofs) = claims.into_iter().unzip();
        assert!(verifier.verify_batch_kzg(proofs, blinded_pks));
        end_timer!(t_verify_batch);
    }

    #[test]
    fn test_ring_proof_id() {
        _test_ring_proof::<w3f_pcs::pcs::IdentityCommitment>(2usize.pow(10), 1);
    }
}
