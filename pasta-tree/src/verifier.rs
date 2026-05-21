use crate::auth_path::blinded::BlindedAuthenticationPath;
use crate::{CurveTreeProof, CycleParams, CycleSide, CycleSideParams, CycleSideProof};
use ark_ec::CurveGroup;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ff::PrimeField;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::verifier::{PcsOpeningAt2Points, PlonkVerifier};
use w3f_ring_proof::ArkTranscript;
use w3f_ring_proof::piop::verifier::PiopVerifier;

impl<F0, F1, C0, C1> CycleParams<Projective<C0>, Projective<C1>>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: SWCurveConfig<BaseField = F1, ScalarField = F0>,
    C1: SWCurveConfig<BaseField = F0, ScalarField = F1>,
{
    pub fn verify(
        &self,
        auth_path: BlindedAuthenticationPath<Projective<C0>, Projective<C1>>,
        proof: CurveTreeProof<F0, F1, Projective<C0>, Projective<C1>>,
        _root: CycleSide<Affine<C0>, Affine<C1>>,
    ) -> bool {
        // println!("leaf = {}", auth_path.c0_path[0]);
        // println!("root = {:?}", root);
        let _c0_x_coords: Vec<Affine<C0>> = proof
            .c0_proof
            .fixed_columns_committed
            .iter()
            .map(|c| c.points[0].0)
            .collect();
        let _c1_x_coords: Vec<Affine<C1>> = proof
            .c1_proof
            .fixed_columns_committed
            .iter()
            .map(|c| c.points[0].0)
            .collect();
        // match root {
        //     CycleSide::C0(c0_root) => {
        //         assert_eq!(c0_root, c0_x_coords[c0_x_coords.len() - 1]);
        //         assert_eq!(auth_path.c1_path, c1_x_coords);
        //         assert_eq!(auth_path.c0_path[1..], c0_x_coords[..c0_x_coords.len() - 1]);
        //     }
        //     CycleSide::C1(c1_root) => {
        //         assert_eq!(c1_root, c1_x_coords[c1_x_coords.len() - 1]);
        //         assert_eq!(auth_path.c1_path, c1_x_coords[..c1_x_coords.len() - 1]);
        //         assert_eq!(auth_path.c0_path[1..], c0_x_coords);
        //     }
        // }
        let c0_proof = self
            .c0_params
            .verify_side(auth_path.c1_path, proof.c0_proof);
        assert!(c0_proof);
        let c1_proof = self
            .c1_params
            .verify_side(auth_path.c0_path, proof.c1_proof);
        assert!(c1_proof);
        c0_proof && c1_proof
    }
}

impl<C: CurveGroup, G: SWCurveConfig<BaseField = C::ScalarField, ScalarField = C::BaseField>>
    CycleSideParams<C, Affine<G>>
{
    pub fn verify_side(
        &self,
        blinded_path: Vec<Affine<G>>,
        side_proof: CycleSideProof<C::ScalarField, C>,
    ) -> bool {
        let plonk_verifier: PlonkVerifier<C::ScalarField, HidingIpa<C>, _> = PlonkVerifier::init(
            self.pcs_params.vk(),
            &blinded_path,
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        let mut polys = Vec::with_capacity(side_proof.piop_proofs.len() * 9);
        let mut coords = Vec::with_capacity(side_proof.piop_proofs.len() * 9);
        let mut vals = Vec::with_capacity(side_proof.piop_proofs.len() * 9);

        for ((blinded_node, piop_proof), parent) in blinded_path
            .iter()
            .zip(side_proof.piop_proofs.into_iter())
            .zip(side_proof.fixed_columns_committed.into_iter())
        {
            let (challenges, _rng) = plonk_verifier.restore_challenges(
                blinded_node,
                &piop_proof,
                // '1' accounts for the quotient polynomial that is aggregated together with the columns
                8,
                7,
            );
            let seed = self.piop_params.seed;
            let seed_plus_result = (seed + blinded_node).into_affine();
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
            // println!("zeta = {zeta}, q(z) = {}", vals_at_zeta[vals_at_zeta.len() - 1]);
            coords.extend(vec![vec![zeta]; open_at_zeta.len()]);
            polys.extend(open_at_zeta);
            coords.extend(vec![vec![zeta_omega]; open_at_zeta_omega.len()]);
            polys.extend(open_at_zeta_omega);
            vals.extend(vals_at_zeta.into_iter().map(|v| vec![v]));
            vals.extend(vals_at_zeta_omega.into_iter().map(|v| vec![v]));
        }

        let mut todo = side_proof.todo;
        let valid = Shplonk::<C::ScalarField, HidingIpa<C>>::verify_many(
            &self.pcs_params.vk(),
            &polys,
            side_proof.pcs_proof,
            &coords,
            &vals,
            &mut todo,
        );
        valid
    }
}
