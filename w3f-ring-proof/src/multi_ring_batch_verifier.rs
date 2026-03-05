use ark_ec::pairing::Pairing;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::CurveGroup;
use ark_std::rand::RngCore;
use w3f_pcs::pcs::kzg::params::KzgVerifierKey;
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::PCS;
use w3f_plonk_common::kzg_acc::KzgAccumulator;
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::transcript::PlonkTranscript;
use w3f_plonk_common::verifier::Challenges;

use crate::piop::PiopVerifier;
use crate::ring_verifier::RingVerifier;
use crate::RingProof;

/// A ring proof preprocessed for multi-ring batch verification.
///
/// Holds a reference to the `RingVerifier` that was used during preparation,
/// so that `push_prepared` can access the correct ring's transcript prelude.
pub struct PreparedMultiRingItem<'a, E, J, T>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    verifier: &'a RingVerifier<E::ScalarField, KZG<E>, J, T>,
    piop: PiopVerifier<E::ScalarField, <KZG<E> as PCS<E::ScalarField>>::C, Affine<J>>,
    proof: RingProof<E::ScalarField, KZG<E>>,
    challenges: Challenges<E::ScalarField>,
    entropy: [u8; 32],
}

/// Accumulating batch verifier for ring proofs across multiple rings.
///
/// Unlike `KzgBatchVerifier` which is tied to a single ring,
/// this verifier can accumulate proofs from different rings (keysets)
/// into a single batched pairing check.
///
/// All rings must share the same KZG SRS (same `KzgVerifierKey`).
pub struct MultiRingBatchVerifier<E: Pairing> {
    acc: KzgAccumulator<E>,
}

impl<E: Pairing> MultiRingBatchVerifier<E> {
    /// Creates a new multi-ring batch verifier.
    pub fn new(kzg_vk: KzgVerifierKey<E>) -> Self {
        Self {
            acc: KzgAccumulator::<E>::new(kzg_vk),
        }
    }

    /// Prepares a ring proof for batch verification without accumulating it.
    ///
    /// The returned item holds a reference to the `verifier` and is independent
    /// of the accumulator state, so multiple proofs (even from different rings)
    /// can be prepared in parallel.
    pub fn prepare<'a, J, T>(
        verifier: &'a RingVerifier<E::ScalarField, KZG<E>, J, T>,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) -> PreparedMultiRingItem<'a, E, J, T>
    where
        J: TECurveConfig<BaseField = E::ScalarField>,
        T: PlonkTranscript<E::ScalarField, KZG<E>>,
    {
        let (challenges, mut rng) = verifier.plonk_verifier.restore_challenges(
            &result,
            &proof,
            PiopVerifier::<E::ScalarField, <KZG<E> as PCS<_>>::C, Affine<J>>::N_COLUMNS + 1,
            PiopVerifier::<E::ScalarField, <KZG<E> as PCS<_>>::C, Affine<J>>::N_CONSTRAINTS,
        );
        let seed = verifier.piop_params.seed;
        let seed_plus_result = (seed + result).into_affine();
        let domain_at_zeta = verifier.piop_params.domain.evaluate(challenges.zeta);
        let piop = PiopVerifier::<_, _, Affine<J>>::init(
            domain_at_zeta,
            verifier.fixed_columns_committed.clone(),
            proof.column_commitments.clone(),
            proof.columns_at_zeta.clone(),
            (seed.x, seed.y),
            (seed_plus_result.x, seed_plus_result.y),
        );

        let mut entropy = [0_u8; 32];
        rng.fill_bytes(&mut entropy);

        PreparedMultiRingItem {
            verifier,
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
    pub fn push_prepared<J, T>(&mut self, item: PreparedMultiRingItem<'_, E, J, T>)
    where
        J: TECurveConfig<BaseField = E::ScalarField>,
        T: PlonkTranscript<E::ScalarField, KZG<E>>,
    {
        let mut ts = item.verifier.plonk_verifier.transcript_prelude.clone();
        ts._add_serializable(b"batch-entropy", &item.entropy);
        self.acc
            .accumulate(item.piop, item.proof, item.challenges, &mut ts.to_rng());
    }

    /// Adds a ring proof to the batch, preparing and accumulating it immediately.
    pub fn push<J, T>(
        &mut self,
        verifier: &RingVerifier<E::ScalarField, KZG<E>, J, T>,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) where
        J: TECurveConfig<BaseField = E::ScalarField>,
        T: PlonkTranscript<E::ScalarField, KZG<E>>,
    {
        let item = Self::prepare(verifier, proof, result);
        self.push_prepared(item);
    }

    /// Verifies all accumulated proofs in a single batched pairing check.
    pub fn verify(&self) -> bool {
        self.acc.verify()
    }
}
