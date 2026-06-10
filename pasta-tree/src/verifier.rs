use std::collections::BTreeSet;
use std::marker::PhantomData;
use crate::{ArkTranscript, BatchSideProof, CurveTreeProof2};
use crate::auth_path::blinded::BlindedAuthenticationPath;
use crate::{
    AffinePoint, CircuitParams, CurveModel, CycleParams, CycleSideParams, ProjectivePoint,
};
use crate::{CurveTreeProof, CycleSideProof};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::batch::BatchVerifier;
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::verifier::{PcsOpeningAt2Points, PlonkVerifier};

impl<C0, C1, P0, P1> CycleParams<C0, C1, P0, P1>
where
    C0: CurveModel<BaseField: PrimeField>,
    C1: CurveModel<BaseField=C0::ScalarField, ScalarField=C0::BaseField>,
    P0: CircuitParams<ProjectivePoint<C0>, C1>,
    P1: CircuitParams<ProjectivePoint<C1>, C0>,
{
    pub fn verify(
        &self,
        auth_path: BlindedAuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        proof: CurveTreeProof<C0, C1, P0, P1>,
        root: AffinePoint<C0>,
    ) -> bool {
        let BlindedAuthenticationPath { c0_path, c1_path } = auth_path;
        let mut c0_parents = c0_path[1..].to_vec();
        c0_parents.push(root);
        let c0_proof = self
            .c0_params
            .verify_side(c1_path.clone(), c0_parents, proof.c0_proof);
        assert!(c0_proof);
        let c1_proof = self.c1_params.verify_side(c0_path, c1_path, proof.c1_proof);
        assert!(c1_proof);
        c0_proof && c1_proof
    }

    pub fn batch_verify<const L: usize>(
        &self,
        auth_path: BlindedAuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        proof: CurveTreeProof2<C0, C1, P0, P1, L>,
        root: AffinePoint<C0>,
    ) -> bool {
        let BlindedAuthenticationPath { c0_path, c1_path } = auth_path;
        let mut c0_parents = c0_path[1..].to_vec();
        c0_parents.push(root);
        let c0_proof = self
            .c0_params
            .verify_batch(c1_path.clone(), c0_parents, proof.c0_proof);
        assert!(c0_proof);
        let c1_proof = self.c1_params.verify_batch(c0_path, c1_path, proof.c1_proof);
        assert!(c1_proof);
        c0_proof && c1_proof
    }
}

impl<C: CurveGroup, G: CurveModel<BaseField=C::ScalarField>, P: CircuitParams<C, G>>
CycleSideParams<C, G, P>
{
    pub fn verify_side(
        &self,
        // selected re-randomized children
        children: Vec<AffinePoint<G>>,
        // parents, re-randomized at the previous step
        parents: Vec<C::Affine>,
        side_proof: CycleSideProof<C, G, P>,
    ) -> bool {
        // let curve_name = &std::any::type_name::<C>()[53..];
        // println!("\n\nverifier {curve_name}\nchildren={children:?}\nparents={parents:?}\n");

        // number of tree levels on this side
        let n_levels = side_proof.piop_proofs.len();
        // per tree level
        let n_to_open = P::VerifierCircuit::N_COLUMNS + 2; // plus the (folded) quotient (chunks) and the linearization polynomial
        // per side
        let n_openings = n_levels * n_to_open;

        let mut polys_to_open = Vec::with_capacity(n_openings);
        let mut at_coords = Vec::with_capacity(n_openings);
        let mut to_values = Vec::with_capacity(n_openings);

        let plonk_verifier: PlonkVerifier<C::ScalarField, HidingIpa<C>, _> = PlonkVerifier::init(
            self.pcs_params.vk(),
            &(), // TODO
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        //TODO: precompute
        let fixed_cols = self.commit_fixed_columns();

        for ((child, parent), level_proof) in children
            .into_iter()
            .zip(parents.into_iter())
            .zip(side_proof.piop_proofs.into_iter())
        {
            let (challenges, _rng) = plonk_verifier.restore_challenges(
                &child,
                &level_proof,
                0,
                P::VerifierCircuit::N_CONSTRAINTS,
            );
            let piop = self.piop_params.verifier_circuit(
                (child, parent),
                &fixed_cols,
                level_proof.column_commitments.clone(),
                level_proof.columns_at_zeta.clone(),
                challenges.zeta,
            );
            let PcsOpeningAt2Points {
                open_at_zeta,
                open_at_zeta_omega,
                zeta,
                zeta_omega,
                vals_at_zeta,
                vals_at_zeta_omega,
            } = plonk_verifier.evaluate_piop(piop, level_proof, challenges);

            // println!(
            //     "zeta = {zeta}, q(zeta) = {}",
            //     vals_at_zeta[vals_at_zeta.len() - 1]
            // );

            at_coords.extend(vec![vec![zeta]; open_at_zeta.len()]);
            polys_to_open.extend(open_at_zeta);
            at_coords.extend(vec![vec![zeta_omega]; open_at_zeta_omega.len()]);
            polys_to_open.extend(open_at_zeta_omega);
            to_values.extend(vals_at_zeta.into_iter().map(|v| vec![v]));
            to_values.extend(vals_at_zeta_omega.into_iter().map(|v| vec![v]));
        }

        let mut todo = side_proof.todo;
        let valid = Shplonk::<C::ScalarField, HidingIpa<C>>::verify_many(
            &self.pcs_params.vk(),
            &polys_to_open,
            side_proof.pcs_proof,
            &at_coords,
            &to_values,
            &mut todo,
        );
        valid
    }

    pub fn verify_batch<const L: usize>(
        &self,
        // selected re-randomized children
        children: Vec<AffinePoint<G>>,
        // parents, re-randomized at the previous step
        parents: Vec<C::Affine>,
        side_proof: BatchSideProof<C, G, P, L>,
    ) -> bool {
        // let curve_name = &std::any::type_name::<C>()[53..];
        // println!("\n\nverifier {curve_name}\nchildren={children:?}\nparents={parents:?}\n");

        // // number of tree levels on this side
        // let n_levels = side_proof.piop_proofs.len();
        // // per tree level
        // let n_to_open = P::VerifierCircuit::N_COLUMNS + 2; // plus the (folded) quotient (chunks) and the linearization polynomial
        // // per side
        // let n_openings = n_levels * n_to_open;
        //
        // let mut polys_to_open = Vec::with_capacity(n_openings);
        // let mut at_coords = Vec::with_capacity(n_openings);
        // let mut to_values = Vec::with_capacity(n_openings);

        //TODO: precompute
        let fixed_cols = self.commit_fixed_columns();
        let piop_proof = side_proof.piop_proof.clone();
        let instance: [AffinePoint<G>; L] = children.clone().try_into().unwrap();

        let plonk_verifier: PlonkVerifier<C::ScalarField, HidingIpa<C>, _> = PlonkVerifier::init(
            self.pcs_params.vk(),
            &(), // TODO
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        let (challenges, _rng) = plonk_verifier.restore_challenges(
            &instance,
            &piop_proof,
            0,
            L * P::VerifierCircuit::N_CONSTRAINTS,
        );
        let zeta_ = challenges.zeta;
        println!("zeta = {zeta_}");

        let batch_piop: [_; L] = children.into_iter()
            .zip(parents.into_iter())
            .zip(piop_proof.column_commitments.into_iter())
            .zip(piop_proof.columns_at_zeta.into_iter())
            .map(|(((child, parent), cols), evals)|
                self.piop_params.verifier_circuit(
                    (child, parent),
                    &fixed_cols,
                    cols,
                    evals,
                    challenges.zeta,
                )).collect::<Vec<_>>().try_into().unwrap_or_else(|_| panic!("wtf"));
        let batch_piop = BatchVerifier(batch_piop, PhantomData, PhantomData);

        let PcsOpeningAt2Points {
            open_at_zeta,
            open_at_zeta_omega,
            zeta,
            zeta_omega,
            vals_at_zeta,
            vals_at_zeta_omega,
        } = plonk_verifier.evaluate_piop(batch_piop, side_proof.piop_proof, challenges);
        debug_assert_eq!(zeta, zeta_);
        println!("q(zeta) = {}", vals_at_zeta[vals_at_zeta.len() - 1]);

        let mut at_coords = vec![vec![zeta]; open_at_zeta.len()];
        let mut polys_to_open = open_at_zeta;
        at_coords.extend(vec![vec![zeta_omega]; open_at_zeta_omega.len()]);
        polys_to_open.extend(open_at_zeta_omega.clone());
        let to_values: Vec<Vec<_>> = vals_at_zeta.into_iter()
            .chain(vals_at_zeta_omega.into_iter())
            .map(|v| vec![v])
            .collect();

        let lin = open_at_zeta_omega[0].0;
        println!("C_lin = {lin}");
        for (i, ((p, z), v)) in polys_to_open.iter()
            .zip(at_coords.iter().map(|z| z.first().unwrap()))
            .zip(to_values.iter().map(|v| v.first().unwrap()))
            .enumerate() {
            println!("{i}: z={z}, v={v}");
        }

        let mut todo = side_proof.todo;
        let valid = Shplonk::<C::ScalarField, HidingIpa<C>>::verify_many(
            &self.pcs_params.vk(),
            &polys_to_open,
            side_proof.pcs_proof,
            &at_coords,
            &to_values,
            &mut todo,
        );
        valid
    }
}
