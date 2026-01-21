use ark_ec::pairing::Pairing;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::{RawVerifierKey, PCS};
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::transcript::PlonkTranscript;
use w3f_plonk_common::verifier::PlonkVerifier;

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

impl<E, Jubjub, T> RingVerifier<E::ScalarField, KZG<E>, Jubjub, T>
where
    E: Pairing,
    Jubjub: TECurveConfig<BaseField = E::ScalarField>,
    T: PlonkTranscript<E::ScalarField, KZG<E>>,
{
    // Verifies a batch of proofs against the same ring.
    pub fn verify_batch_kzg(
        &self,
        proofs: Vec<RingProof<E::ScalarField, KZG<E>>>,
        results: Vec<Affine<Jubjub>>,
    ) -> bool {
        for (proof, result) in proofs.into_iter().zip(results) {
            let (challenges, mut rng) = self.plonk_verifier.restore_challenges(
                &result,
                &proof,
                // '1' accounts for the quotient polynomial that is aggregated together with the columns
                PiopVerifier::<E::ScalarField, <KZG<E> as PCS<_>>::C, Affine<Jubjub>>::N_COLUMNS + 1,
                PiopVerifier::<E::ScalarField, <KZG<E> as PCS<_>>::C, Affine<Jubjub>>::N_CONSTRAINTS,
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
            let res = self
                .plonk_verifier
                .verify(piop, proof, challenges, &mut rng);
            if !res {
                return false;
            }
        }
        true
    }
}
