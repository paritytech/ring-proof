use ark_ec::pairing::Pairing;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::{RawVerifierKey, PCS};
use w3f_plonk_common::kzg_acc::KzgAccumulator;
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::transcript::PlonkTranscript;
use w3f_plonk_common::verifier::{Challenges, PlonkVerifier};

use crate::piop::params::PiopParams;
use crate::piop::{FixedColumnsCommitted, PiopVerifier, VerifierKey};
use crate::{ArkTranscript, RingProof};

pub struct RingVerifier<F, CS, Jubjub, T = ArkTranscript>
where
    F: PrimeField,
    CS: PCS<F>,
    Jubjub: TECurveConfig<BaseField = F>,
    T: PlonkTranscript<F, CS>,
{
    piop_params: PiopParams<F, Jubjub>,
    fixed_columns_committed: FixedColumnsCommitted<F, CS::C>,
    plonk_verifier: PlonkVerifier<F, CS, T>,
}

impl<F, CS, Jubjub, T> RingVerifier<F, CS, Jubjub, T>
where
    F: PrimeField,
    CS: PCS<F>,
    Jubjub: TECurveConfig<BaseField = F>,
    T: PlonkTranscript<F, CS>,
{
    pub fn init(
        verifier_key: VerifierKey<F, CS>,
        piop_params: PiopParams<F, Jubjub>,
        empty_transcript: T,
    ) -> Self {
        let pcs_vk = verifier_key.pcs_raw_vk.prepare();
        let plonk_verifier = PlonkVerifier::init(pcs_vk, &verifier_key, empty_transcript);
        Self {
            piop_params,
            fixed_columns_committed: verifier_key.fixed_columns_committed,
            plonk_verifier,
        }
    }

    pub fn verify(&self, proof: RingProof<F, CS>, result: Affine<Jubjub>) -> bool {
        let (challenges, mut rng) = self.plonk_verifier.restore_challenges(
            &result,
            &proof,
            // '1' accounts for the quotient polynomial that is aggregated together with the columns
            PiopVerifier::<F, CS::C, Affine<Jubjub>>::N_COLUMNS + 1,
            PiopVerifier::<F, CS::C, Affine<Jubjub>>::N_CONSTRAINTS,
        );
        let seed = self.piop_params.seed;
        let seed_plus_result = (seed + result).into_affine();
        let domain_at_zeta = self.piop_params.domain.evaluate(challenges.zeta);
        let piop = PiopVerifier::<_, _, Affine<Jubjub>>::init(
            domain_at_zeta,
            self.fixed_columns_committed.clone(),
            proof.column_commitments.clone(),
            proof.columns_at_zeta.clone(),
            (seed.x, seed.y),
            (seed_plus_result.x, seed_plus_result.y),
        );

        self.plonk_verifier
            .verify(piop, proof, challenges, &mut rng)
    }

    pub fn piop_params(&self) -> &PiopParams<F, Jubjub> {
        &self.piop_params
    }

    pub fn verify_batch(
        &self,
        proofs: Vec<RingProof<F, CS>>,
        results: Vec<Affine<Jubjub>>,
    ) -> bool {
        for (proof, result) in proofs.into_iter().zip(results) {
            let res = self.verify(proof, result);
            if !res {
                return false;
            }
        }
        true
    }
}

/// Accumulating batch verifier for ring proofs using KZG polynomial commitment scheme.
pub struct KzgBatchVerifier<E, J, T = ArkTranscript>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    pub acc: KzgAccumulator<E>,
    pub verifier: RingVerifier<E::ScalarField, KZG<E>, J, T>,
}

/// A ring proof that has been preprocessed for batch verification.
pub struct PreparedBatchItem<E, J>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
{
    piop: PiopVerifier<E::ScalarField, <KZG<E> as PCS<E::ScalarField>>::C, Affine<J>>,
    proof: RingProof<E::ScalarField, KZG<E>>,
    challenges: Challenges<E::ScalarField>,
    entropy: [u8; 32],
}

impl<E, J, T> KzgBatchVerifier<E, J, T>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    /// Prepares a ring proof for batch verification without accumulating it.
    ///
    /// Returns a `PreparedBatchItem` that can later be passed to `push_prepared`.
    ///
    /// This method is independent of the accumulator state, so multiple proofs can be
    /// prepared in parallel (e.g., using `rayon`). Each prepared item is in the order
    /// of a few KB, so for large batches you may want to prepare and push incrementally
    /// rather than holding all prepared items in memory at once.
    pub fn prepare(
        &self,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) -> PreparedBatchItem<E, J> {
        let (challenges, mut rng) = self.verifier.plonk_verifier.restore_challenges(
            &result,
            &proof,
            // '1' accounts for the quotient polynomial that is aggregated together with the columns
            PiopVerifier::<E::ScalarField, <KZG<E> as PCS<_>>::C, Affine<J>>::N_COLUMNS + 1,
            PiopVerifier::<E::ScalarField, <KZG<E> as PCS<_>>::C, Affine<J>>::N_CONSTRAINTS,
        );
        let seed = self.verifier.piop_params.seed;
        let seed_plus_result = (seed + result).into_affine();
        let domain_at_zeta = self.verifier.piop_params.domain.evaluate(challenges.zeta);
        let piop = PiopVerifier::<_, _, Affine<J>>::init(
            domain_at_zeta,
            self.verifier.fixed_columns_committed.clone(),
            proof.column_commitments.clone(),
            proof.columns_at_zeta.clone(),
            (seed.x, seed.y),
            (seed_plus_result.x, seed_plus_result.y),
        );

        // Pick some entropy from plonk verifier for later usage
        let mut entropy = [0_u8; 32];
        rng.fill_bytes(&mut entropy);

        PreparedBatchItem {
            piop,
            proof,
            challenges,
            entropy,
        }
    }

    /// Accumulates a previously prepared proof into the batch.
    ///
    /// This is the second step of the two-phase batch verification workflow:
    /// 1. `prepare` - can be parallelized across multiple proofs
    /// 2. `push_prepared` - must be called sequentially (mutates the accumulator)
    ///
    /// For simpler usage where parallelism isn't needed, use `push` instead.
    pub fn push_prepared(&mut self, item: PreparedBatchItem<E, J>) {
        let mut ts = self.verifier.plonk_verifier.transcript_prelude.clone();
        ts._add_serializable(b"batch-entropy", &item.entropy);
        self.acc
            .accumulate(item.piop, item.proof, item.challenges, &mut ts.to_rng());
    }

    /// Adds a ring proof to the batch, preparing and accumulating it immediately.
    ///
    /// The proof's pairing equation is aggregated into the internal accumulator.
    /// Call `verify` after pushing all proofs to perform the batched verification.
    pub fn push(&mut self, proof: RingProof<E::ScalarField, KZG<E>>, result: Affine<J>) {
        let item = self.prepare(proof, result);
        self.push_prepared(item);
    }

    /// Verifies all accumulated proofs in a single batched pairing check.
    pub fn verify(&self) -> bool {
        self.acc.verify()
    }
}

impl<E, J, T> RingVerifier<E::ScalarField, KZG<E>, J, T>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    /// Build a new batch verifier.
    pub fn kzg_batch_verifier(self) -> KzgBatchVerifier<E, J, T> {
        KzgBatchVerifier {
            acc: KzgAccumulator::<E>::new(self.plonk_verifier.pcs_vk.clone()),
            verifier: self,
        }
    }

    /// Verifies a batch of proofs against the same ring.
    pub fn verify_batch_kzg(
        self,
        proofs: Vec<RingProof<E::ScalarField, KZG<E>>>,
        results: Vec<Affine<J>>,
    ) -> bool {
        let mut batch = self.kzg_batch_verifier();
        for (proof, result) in proofs.into_iter().zip(results) {
            batch.push(proof, result);
        }
        batch.verify()
    }
}
