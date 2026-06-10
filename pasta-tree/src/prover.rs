use crate::{ArkTranscript, BatchLevelProof, BatchSideProof, CurveTreeProof2};
use crate::auth_path::blinded::BlindedAuthenticationPath;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::auth_path::path::AuthenticationPath;
use crate::{
    AffinePoint, CircuitParams, CurveModel, CycleParams, CycleSideParams, ProjectivePoint,
};
use crate::{Coeffs, CurveTreeProof, CycleSideProof};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_poly::Polynomial;
use ark_std::rand::Rng;
use ark_std::{UniformRand, end_timer, start_timer};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::batch::BatchProver;
use w3f_plonk_common::piop::{ProverPiop, VerifierPiop};
use w3f_plonk_common::Proof;
use w3f_plonk_common::prover::{PcsOpeningAt2Points, PlonkProver};

impl<C0, C1, P0, P1> CycleParams<C0, C1, P0, P1>
where
    C0: CurveModel<BaseField: PrimeField>,
    C1: CurveModel<BaseField=C0::ScalarField, ScalarField=C0::BaseField>,
    P0: CircuitParams<ProjectivePoint<C0>, C1>,
    P1: CircuitParams<ProjectivePoint<C1>, C0>,
{
    pub fn prove<R: Rng>(
        &self,
        auth_path: AuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        rng: &mut R,
    ) -> (
        BlindedAuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        CurveTreeProof<C0, C1, P0, P1>,
    ) {
        let auth_path_with_bf = auth_path.with_blinding(rng);
        let blinded_auth_path =
            auth_path_with_bf.apply_bfs(&self.c0_params.pcs_params, &self.c1_params.pcs_params);
        let auth_path = blinded_auth_path.clone();
        let c0_proof =
            self.c0_params
                .prove_side(blinded_auth_path.c1_path, auth_path_with_bf.c1_path, rng);
        let c1_proof =
            self.c1_params
                .prove_side(blinded_auth_path.c0_path, auth_path_with_bf.c0_path, rng);
        (auth_path, CurveTreeProof { c0_proof, c1_proof })
    }

    pub fn batch_prove<R: Rng, const L: usize>(
        &self,
        auth_path: AuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        rng: &mut R,
    ) -> (
        BlindedAuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        CurveTreeProof2<C0, C1, P0, P1, L>,
    ) {
        let auth_path_with_bf = auth_path.with_blinding(rng);
        let blinded_auth_path =
            auth_path_with_bf.apply_bfs(&self.c0_params.pcs_params, &self.c1_params.pcs_params);
        let auth_path = blinded_auth_path.clone();
        let c1_path: [_; L] = auth_path_with_bf.c1_path.try_into().unwrap();
        let c0_path: [_; L] = auth_path_with_bf.c0_path.try_into().unwrap();
        let c0_proof = self.c0_params.batch_prove_side(blinded_auth_path.c1_path, c1_path, rng);
        let c1_proof = self.c1_params.batch_prove_side(blinded_auth_path.c0_path, c0_path, rng);
        (auth_path, CurveTreeProof2 { c0_proof, c1_proof })
    }
}

impl<C: CurveGroup, G: CurveModel<BaseField=C::ScalarField>, P: CircuitParams<C, G>>
CycleSideParams<C, G, P>
{
    pub fn prove_side<R: Rng>(
        &self,
        blinded_path: Vec<AffinePoint<G>>,
        witness: Vec<LevelWitnessWithBlinding<AffinePoint<G>>>,
        rng: &mut R,
    ) -> CycleSideProof<C, G, P> {
        let curve_name = &std::any::type_name::<C>()[53..];
        // println!("\n\nprover {curve_name}\nchildren={blinded_path:?}\n");
        let n_levels = witness.len(); // number of tree levels on this side
        debug_assert_eq!(blinded_path.len(), n_levels);
        let mut piop_proofs = Vec::with_capacity(n_levels);

        // per tree level
        let n_columns = P::VerifierCircuit::N_COLUMNS;
        let n_to_commit = n_columns + 3; // plus the quotient chunks
        let n_to_open = n_columns + 2; // plus the (folded) quotient (chunks) and the linearization polynomial

        // per side
        let n_openings = n_levels * n_to_open;
        let mut polys_to_open = Vec::with_capacity(n_openings);
        let mut at_coords = Vec::with_capacity(n_openings);
        let mut with_bfs = Vec::with_capacity(n_openings);

        let plonk_prover = PlonkProver::<C::ScalarField, HidingIpa<C>, _>::init(
            self.pcs_params.ck(),
            (),
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        let t_commit_side = start_timer!(|| format!(
            "Committing {n_levels} x {n_to_commit} polynomials to {curve_name}"
        ));
        for (level, blinded_node) in witness.into_iter().zip(blinded_path.into_iter()) {
            // let t_commit_level = start_timer!(|| format!("Committing {n_to_commit} polynomials"));
            let piop: P::ProverCircuit =
                <P as CircuitParams<C, G>>::prover_circuit(&self.piop_params, level.clone());
            let result =
                <P::ProverCircuit as ProverPiop<C::ScalarField, WrappedAffine<C>>>::result(&piop);
            debug_assert_eq!(result, blinded_node);
            let (pcs_openings, piop_proof, _transcript) = plonk_prover.reduce_to_pcs_opening(piop);
            piop_proofs.push(piop_proof);
            let PcsOpeningAt2Points {
                polys_at_zeta,
                polys_at_zeta_omega,
                zeta,
                zeta_omega,
            } = pcs_openings;

            // use ark_poly::Polynomial;
            // println!(
            //     "zeta = {zeta}, q(zeta) = {}",
            //     polys_at_zeta[polys_at_zeta.len() - 1].evaluate(&zeta)
            // );

            at_coords.extend(vec![BTreeSet::from([zeta]); polys_at_zeta.len()]);
            polys_to_open.extend(polys_at_zeta);
            at_coords.extend(vec![
                BTreeSet::from([zeta_omega]);
                polys_at_zeta_omega.len()
            ]);
            polys_to_open.extend(polys_at_zeta_omega);
            with_bfs.push(level.parent_bf);
            with_bfs.resize(polys_to_open.len(), C::ScalarField::zero());
            // end_timer!(t_commit_level);
        }
        end_timer!(t_commit_side);

        let t_open = start_timer!(|| format!(
            "Opening {n_openings} polynomials, max_degree = {}",
            polys_to_open.iter().map(|p| p.degree()).max().unwrap()
        ));
        let todo = Coeffs(C::ScalarField::rand(rng), C::ScalarField::rand(rng));
        let pcs_proof = Shplonk::<C::ScalarField, HidingIpa<C>>::open_many_hiding(
            &self.pcs_params,
            &polys_to_open,
            &with_bfs,
            &at_coords,
            &mut todo.clone(),
            rng,
        );
        end_timer!(t_open);

        let proof = CycleSideProof {
            piop_proofs,
            pcs_proof,
            todo,
        };
        proof
    }

    pub fn batch_prove_side<R: Rng, const L: usize>(
        &self,
        blinded_path: Vec<AffinePoint<G>>,
        witness: [LevelWitnessWithBlinding<AffinePoint<G>>; L],
        rng: &mut R,
    ) -> BatchSideProof<C, G, P, L> {
        let curve_name = &std::any::type_name::<C>()[53..];
        // println!("\n\nprover {curve_name}\nchildren={blinded_path:?}\n");
        // let n_levels = witness.len(); // number of tree levels on this side
        // debug_assert_eq!(blinded_path.len(), n_levels);
        // let mut piop_proofs = Vec::with_capacity(n_levels);
        //
        // // per tree level
        let n_columns = P::VerifierCircuit::N_COLUMNS;
        let n_to_commit = L * n_columns + 3; // plus the quotient chunks
        let n_to_open = L * n_columns + 2; // plus the (folded) quotient (chunks) and the linearization polynomial

        let plonk_prover = PlonkProver::<C::ScalarField, HidingIpa<C>, _>::init(
            self.pcs_params.ck(),
            (),
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        let parent_bfs: Vec<_> = witness.iter().map(|level| level.parent_bf).collect();
        let batch_piop = witness.map(|level| self.piop_params.prover_circuit(level));
        let batch_piop = BatchProver(batch_piop, PhantomData, PhantomData);


        let t_commit_side = start_timer!(|| format!(
            "Committing {L}x{n_columns}+3 = {n_to_commit} polynomials to {curve_name}"
        ));
        let (pcs_openings, piop_proof, _transcript) = plonk_prover.reduce_to_pcs_opening(batch_piop);
        end_timer!(t_commit_side);

        let PcsOpeningAt2Points {
            polys_at_zeta,
            polys_at_zeta_omega,
            zeta,
            zeta_omega,
        } = pcs_openings;
        let mut at_coords = vec![BTreeSet::from([zeta]); polys_at_zeta.len()];
        let mut polys_to_open = polys_at_zeta;
        at_coords.extend(vec![BTreeSet::from([zeta_omega]); polys_at_zeta_omega.len()]);
        polys_to_open.extend(polys_at_zeta_omega);
        let with_bfs = vec![C::ScalarField::zero(); polys_to_open.len()];

        let t_open = start_timer!(|| format!(
            "Opening {L}x{n_columns}+2 = {n_to_open} polynomials, max_degree = {}",
            polys_to_open.iter().map(|p| p.degree()).max().unwrap()
        ));
        let todo = Coeffs(C::ScalarField::rand(rng), C::ScalarField::rand(rng));
        let pcs_proof = Shplonk::<C::ScalarField, HidingIpa<C>>::open_many_hiding(
            &self.pcs_params,
            &polys_to_open,
            &with_bfs,
            &at_coords,
            &mut todo.clone(),
            rng,
        );
        end_timer!(t_open);

        let proof = BatchSideProof {
            piop_proof,
            pcs_proof,
            todo,
        };
        proof
    }
}
