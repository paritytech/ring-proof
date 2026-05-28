use crate::auth_path::blinded::BlindedAuthenticationPath;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::auth_path::path::AuthenticationPath;
use crate::circuit2::prover::PiopProver;
use crate::verifier::V;
use crate::{Coeffs, CurveTreeProof, CycleParams, CycleSideParams, CycleSideProof};
use ark_ec::CurveGroup;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ff::{PrimeField, Zero};
use ark_std::UniformRand;
use ark_std::rand::Rng;
use std::collections::BTreeSet;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::piop::{ProverPiop, VerifierPiop};
use w3f_plonk_common::prover::{PcsOpeningAt2Points, PlonkProver};
use w3f_ring_proof::ArkTranscript;

impl<F0, F1, C0, C1> CycleParams<Projective<C0>, Projective<C1>>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: SWCurveConfig<BaseField = F1, ScalarField = F0>,
    C1: SWCurveConfig<BaseField = F0, ScalarField = F1>,
{
    pub fn prove<R: Rng>(
        &self,
        auth_path: AuthenticationPath<Projective<C0>, Projective<C1>>,
        rng: &mut R,
    ) -> (
        BlindedAuthenticationPath<Projective<C0>, Projective<C1>>,
        CurveTreeProof<F0, F1, Projective<C0>, Projective<C1>>,
    ) {
        let auth_path_with_bf = auth_path.with_blinding(rng);
        let blinded_auth_path = auth_path_with_bf.apply_bfs(&self);
        let auth_path = blinded_auth_path.clone();
        let c0_proof =
            self.c0_params
                .prove_side(blinded_auth_path.c1_path, auth_path_with_bf.c1_path, rng);
        let c1_proof =
            self.c1_params
                .prove_side(blinded_auth_path.c0_path, auth_path_with_bf.c0_path, rng);
        (auth_path, CurveTreeProof { c0_proof, c1_proof })
    }
}

impl<C: CurveGroup, G: SWCurveConfig<BaseField = C::ScalarField, ScalarField = C::BaseField>>
    CycleSideParams<C, Affine<G>>
{
    pub fn prove_side<R: Rng>(
        &self,
        blinded_path: Vec<Affine<G>>,
        witness: Vec<LevelWitnessWithBlinding<Affine<G>>>,
        rng: &mut R,
    ) -> CycleSideProof<C> {
        // let mut s = std::any::type_name::<C>();
        // s = &s[70..s.len()];
        // println!("\n\nprover {s}\nchildren={blinded_path:?}\n");

        debug_assert_eq!(blinded_path.len(), witness.len());
        let n_polys = V::<C, G>::N_COLUMNS + 2; // plus the quotient and the linearization polys
        let mut piop_proofs = Vec::with_capacity(witness.len());
        let mut polys = Vec::with_capacity(witness.len() * n_polys);
        let mut coords = Vec::with_capacity(witness.len() * n_polys);
        let mut bfs = Vec::with_capacity(witness.len() * n_polys);

        let plonk_prover = PlonkProver::<C::ScalarField, HidingIpa<C>, _>::init(
            self.pcs_params.ck(),
            (),
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        for (level, blinded_node) in witness.into_iter().zip(blinded_path.into_iter()) {
            let piop = self.piop_params.prover_piop(level.clone());
            let blinded_node_ = <PiopProver<Affine<G>> as ProverPiop<
                C::ScalarField,
                WrappedAffine<C>,
            >>::result(&piop);
            debug_assert_eq!(blinded_node_, blinded_node);
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

            coords.extend(vec![BTreeSet::from([zeta]); polys_at_zeta.len()]);
            polys.extend(polys_at_zeta);
            coords.extend(vec![
                BTreeSet::from([zeta_omega]);
                polys_at_zeta_omega.len()
            ]);
            polys.extend(polys_at_zeta_omega);
            bfs.push(level.parent_bf);
            bfs.resize(polys.len(), C::ScalarField::zero());
        }

        let todo = Coeffs(C::ScalarField::rand(rng), C::ScalarField::rand(rng));
        let pcs_proof = Shplonk::<C::ScalarField, HidingIpa<C>>::open_many_hiding(
            &self.pcs_params,
            &polys,
            &bfs,
            &coords,
            &mut todo.clone(),
            rng,
        );

        let proof = CycleSideProof {
            piop_proofs,
            pcs_proof,
            todo,
        };
        proof
    }
}
