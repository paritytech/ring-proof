use crate::CircuitParams;
use crate::auth_path::blinded::BlindedAuthenticationPath;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::auth_path::path::AuthenticationPath;
use crate::circuit_tall::params::PiopParams;
use crate::circuit_tall::prover::PiopProver;
use crate::{Coeffs, CurveTreeProof, CycleParams, CycleSideParams, CycleSideProof};
use ark_ec::{AffineRepr, CurveGroup};
// use ark_ec::short_weierstrass::{Affine as SwAffine, Projective, SWCurveConfig};
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
use crate::circuit_tall::verifier::PiopVerifier;

impl<F0, F1, C0, C1> CycleParams<C0, C1>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: CurveGroup<BaseField = F1, ScalarField = F0>,
    C1: CurveGroup<BaseField = F0, ScalarField = F1>,
{
    pub fn prove<R: Rng>(
        &self,
        auth_path: AuthenticationPath<C0, C1>,
        rng: &mut R,
    ) -> (
        BlindedAuthenticationPath<C0, C1>,
        CurveTreeProof<C0, C1>,
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

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField, ScalarField = C::BaseField>>
    CycleSideParams<C, G>
{
    pub fn prove_side<R: Rng>(
        &self,
        blinded_path: Vec<G>,
        witness: Vec<LevelWitnessWithBlinding<G>>,
        rng: &mut R,
    ) -> CycleSideProof<C> {
        // let mut s = std::any::type_name::<C>();
        // s = &s[70..s.len()];
        // println!("\n\nprover {s}\nchildren={blinded_path:?}\n");

        debug_assert_eq!(blinded_path.len(), witness.len());
        let n_polys = PiopVerifier::<C, G>::N_COLUMNS + 2; // plus the quotient and the linearization polys
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
            let piop = <PiopParams<G> as CircuitParams<C, G>>::prover_circuit(
                &self.piop_params,
                level.clone(),
            );
            let blinded_node_ = <PiopProver<G> as ProverPiop<
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
