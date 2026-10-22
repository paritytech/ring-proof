use ark_ec::pairing::Pairing;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::CurveGroup;
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::UniformRand;
use w3f_pcs::pcs::kzg::params::KzgVerifierKey;
use w3f_pcs::pcs::kzg::KZG;
use w3f_plonk_common::kzg_acc::{KzgAccumulator, Openings};
use w3f_plonk_common::transcript::PlonkTranscript;

use crate::piop::PiopVerifier;
use crate::ring_verifier::RingVerifier;
use crate::RingProof;

/// A ring proof preprocessed for multi-ring batch verification.
pub struct BatchItem<E: Pairing> {
    openings: Openings<E>,
    entropy: [u8; 32],
}

impl<E: Pairing> BatchItem<E> {
    /// Prepares a ring proof for batch verification without accumulating it.
    ///
    /// The returned item is independent of both any accumulator state and
    /// the originating `RingVerifier`, so multiple proofs (even from
    /// different rings) can be prepared in parallel.
    pub fn new<J, T>(
        verifier: &RingVerifier<E::ScalarField, KZG<E>, J, T>,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) -> Self
    where
        J: TECurveConfig<BaseField = E::ScalarField>,
        T: PlonkTranscript<E::ScalarField, KZG<E>>,
    {
        let (challenges, mut fs_rng) = verifier
            .plonk_verifier
            .restore_fs_with_rng::<PiopVerifier<_, _, Affine<J>>, _, _>(&result, &proof);
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
        fs_rng.fill_bytes(&mut entropy);

        Self {
            openings: Openings::new(piop, proof, challenges),
            entropy,
        }
    }
}

/// Batch verifier for ring proofs across one or more rings.
///
/// Verifies proofs from one or more rings (keysets) in a single batched
/// pairing check. All rings must share the same KZG SRS.
///
/// The batch accepts invalid proofs when their randomized opening errors
/// cancel. A prover who controls the whole batch can make them cancel if the
/// randomizer of each proof depends on that proof only. So the randomizer of
/// every proof must depend on every proof of the batch: the transcript
/// absorbs the entropy of each pushed item, and [`verify`](Self::verify)
/// draws all the randomizers from the final transcript state.
pub struct BatchVerifier<E: Pairing, T>
where
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    kzg_vk: KzgVerifierKey<E>,
    transcript: T,
    items: Vec<Openings<E>>,
}

impl<E: Pairing, T> BatchVerifier<E, T>
where
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    /// Creates a new multi-ring batch verifier.
    pub fn new(kzg_vk: KzgVerifierKey<E>, transcript: T) -> Self {
        Self {
            kzg_vk,
            transcript,
            items: Vec::new(),
        }
    }

    /// Adds a ring proof to the batch.
    pub fn push<J>(
        &mut self,
        verifier: &RingVerifier<E::ScalarField, KZG<E>, J, T>,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) where
        J: TECurveConfig<BaseField = E::ScalarField>,
    {
        self.push_prepared(BatchItem::new(verifier, proof, result));
    }

    /// Adds a prepared [`BatchItem`] to the batch.
    ///
    /// Equivalent to [`push`](Self::push), but splits the work: the caller
    /// builds the [`BatchItem`] (transcript replay, challenge derivation,
    /// PIOP setup) separately. Useful when preparation should be
    /// parallelized. `BatchItem::new` is independent of the batch state, so
    /// multiple items can be built in parallel and then pushed sequentially
    /// here.
    pub fn push_prepared(&mut self, item: BatchItem<E>) {
        self.transcript
            ._add_serializable(b"batch-entropy", &item.entropy);
        self.items.push(item.openings);
    }

    pub(crate) fn randomizers(&self) -> impl Iterator<Item = E::ScalarField> {
        let mut rng = self.transcript.clone().to_rng();
        (0..self.items.len()).map(move |_| E::ScalarField::rand(&mut rng))
    }

    /// Verifies all the pushed proofs in a single batched pairing check.
    pub fn verify(&self) -> bool {
        let mut acc = KzgAccumulator::new(self.kzg_vk.clone());
        for (openings, r) in self.items.iter().zip(self.randomizers()) {
            acc.accumulate(openings, r);
        }
        acc.verify()
    }
}
