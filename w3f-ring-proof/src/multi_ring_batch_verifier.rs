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
pub struct BatchItem<E, J>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
{
    piop: PiopVerifier<E::ScalarField, <KZG<E> as PCS<E::ScalarField>>::C, Affine<J>>,
    proof: RingProof<E::ScalarField, KZG<E>>,
    challenges: Challenges<E::ScalarField>,
    entropy: [u8; 32],
}

impl<E, J> BatchItem<E, J>
where
    E: Pairing,
    J: TECurveConfig<BaseField = E::ScalarField>,
{
    /// Prepares a ring proof for batch verification without accumulating it.
    ///
    /// The returned item is independent of both any accumulator state and
    /// the originating `RingVerifier`, so multiple proofs (even from
    /// different rings) can be prepared in parallel.
    pub fn new<T>(
        verifier: &RingVerifier<E::ScalarField, KZG<E>, J, T>,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) -> Self
    where
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

        Self {
            piop,
            proof,
            challenges,
            entropy,
        }
    }
}

/// Accumulating batch verifier for ring proofs across one or more rings.
///
/// Accumulates proofs from one or more rings (keysets) into a single batched
/// pairing check. All rings must share the same KZG SRS.
///
/// Holds its own transcript instance, cloned on each `push_prepared` so the
/// per-proof entropy can be folded in without touching the originating
/// `RingVerifier`. The transcript's initial state is not load-bearing; any
/// valid `T` works (e.g. the prelude of any ring verifier being batched).
pub struct BatchVerifier<E: Pairing, T>
where
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    acc: KzgAccumulator<E>,
    transcript: T,
}

impl<E: Pairing, T> BatchVerifier<E, T>
where
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    /// Creates a new multi-ring batch verifier.
    pub fn new(kzg_vk: KzgVerifierKey<E>, transcript: T) -> Self {
        Self {
            acc: KzgAccumulator::<E>::new(kzg_vk),
            transcript,
        }
    }

    /// Accumulates a prepared `BatchItem` into the batch.
    pub fn push<J>(&mut self, item: BatchItem<E, J>)
    where
        J: TECurveConfig<BaseField = E::ScalarField>,
    {
        let mut ts = self.transcript.clone();
        ts._add_serializable(b"batch-entropy", &item.entropy);
        self.acc
            .accumulate(item.piop, item.proof, item.challenges, &mut ts.to_rng());
    }

    /// Adds a raw ring proof to the batch.
    ///
    /// Equivalent to `self.push(BatchItem::new(verifier, proof, result))`:
    /// preparation (transcript replay, challenge derivation, PIOP setup) and
    /// accumulation happen internally. Use the two-step form directly when
    /// preparation should be parallelized — `BatchItem::new` is independent
    /// of the accumulator state, so multiple items can be built in parallel
    /// and then pushed sequentially via [`push`](Self::push).
    pub fn push_raw<J>(
        &mut self,
        verifier: &RingVerifier<E::ScalarField, KZG<E>, J, T>,
        proof: RingProof<E::ScalarField, KZG<E>>,
        result: Affine<J>,
    ) where
        J: TECurveConfig<BaseField = E::ScalarField>,
    {
        self.push(BatchItem::new(verifier, proof, result));
    }

    /// Verifies all accumulated proofs in a single batched pairing check.
    pub fn verify(&self) -> bool {
        self.acc.verify()
    }
}
