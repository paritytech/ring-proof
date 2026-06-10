use crate::level::LevelProof;
use crate::{CycleSideParams, IPACommitment};
use ark_ec::CurveGroup;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_std::{end_timer, start_timer};
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::verifier::{PcsOpeningAt2Points, PlonkVerifier};
use w3f_ring_proof::piop::verifier::PiopVerifier;
use w3f_ring_proof::{ArkTranscript, FixedColumnsCommitted, VerifierKey};

impl<C: CurveGroup, G: SWCurveConfig<BaseField = C::ScalarField, ScalarField = C::BaseField>>
    CycleSideParams<C, Affine<G>>
{
    pub fn verify_level(
        &self,
        parent: FixedColumnsCommitted<C::ScalarField, IPACommitment<C>>,
        blinded_child: Affine<G>,
        level_proof: LevelProof<C>,
    ) -> bool {
        let verifier_key: VerifierKey<C::ScalarField, HidingIpa<C>> = VerifierKey {
            pcs_raw_vk: self.pcs_params.raw_vk(),
            fixed_columns_committed: parent.clone(),
        };
        let plonk_verifier: PlonkVerifier<C::ScalarField, HidingIpa<C>, _> = PlonkVerifier::init(
            self.pcs_params.vk(),
            &verifier_key,
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        let LevelProof {
            piop_proof,
            pcs_opening_proof,
            mut todo,
        } = level_proof;

        let (challenges, _rng) = plonk_verifier.restore_challenges(
            &blinded_child,
            &piop_proof,
        );
        let seed = self.piop_params.seed;
        let seed_plus_result = (seed + blinded_child).into_affine();
        let domain_at_zeta = self.piop_params.domain.evaluate(challenges.zeta);
        let piop = PiopVerifier::<_, _, Affine<G>>::init(
            domain_at_zeta,
            parent,
            piop_proof.column_commitments.clone(),
            piop_proof.columns_at_zeta.clone(),
            (seed.x, seed.y),
            (seed_plus_result.x, seed_plus_result.y),
        );

        let PcsOpeningAt2Points {
            open_at_zeta,
            open_at_zeta_omega,
            zeta,
            zeta_omega,
            vals_at_zeta,
            vals_at_zeta_omega,
        } = plonk_verifier.evaluate_piop(piop, piop_proof, challenges);

        let mut coord_vecs = vec![vec![zeta]; open_at_zeta.len()];
        coord_vecs.push(vec![zeta_omega]);
        let polys = [open_at_zeta, open_at_zeta_omega].concat();
        let mut vals: Vec<_> = vals_at_zeta.into_iter().map(|v| vec![v]).collect();
        vals.push(vals_at_zeta_omega);
        let t_verify = start_timer!(|| "Verifying IPA shplonk opening");
        let valid = Shplonk::<C::ScalarField, HidingIpa<C>>::verify_many(
            &self.pcs_params.vk(),
            &polys,
            pcs_opening_proof,
            &coord_vecs,
            &vals,
            &mut todo,
        );
        end_timer!(t_verify);

        valid
    }
}
