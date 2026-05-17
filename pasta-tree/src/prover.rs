use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::auth_path::path::AuthenticationPath;
use crate::ipa_hiding::HidingIpa;
use crate::{Coeffs, CurveTreeProof, CycleParams, CycleSideParams, CycleSideProof, IPACommitment};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use std::collections::BTreeSet;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::piop::ProverPiop;
use w3f_plonk_common::prover::{PcsOpeningAt2Points, PlonkProver};
use w3f_ring_proof::piop::prover::PiopProver;
use w3f_ring_proof::ArkTranscript;
use crate::auth_path::blinded::BlindedAuthenticationPath;

impl<F0, F1, C0, C1> CycleParams<Projective<C0>, Projective<C1>>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: SWCurveConfig<BaseField=F1, ScalarField=F0>,
    C1: SWCurveConfig<BaseField=F0, ScalarField=F1>,
{
    pub fn prove<R: Rng>(&self, auth_path: AuthenticationPath<Projective<C0>, Projective<C1>>, rng: &mut R) -> (
        BlindedAuthenticationPath<Projective<C0>, Projective<C1>>,
        CurveTreeProof<F0, F1, Projective<C0>, Projective<C1>>
    ) {
        let auth_path_with_bf = auth_path.with_blinding(rng);
        let blinded_auth_path = auth_path_with_bf.apply_bfs(&self);
        let blinded_auth_path2 = blinded_auth_path.clone();
        let c0_proof = self.c0_params.prove_side(blinded_auth_path.c1_path, &auth_path_with_bf.c1_path, rng);
        let c1_proof = self.c1_params.prove_side(blinded_auth_path.c0_path, &auth_path_with_bf.c0_path, rng);
        (blinded_auth_path2, CurveTreeProof {
            c0_proof,
            c1_proof,
        })
    }
}

impl<C: CurveGroup, G: SWCurveConfig<BaseField=C::ScalarField, ScalarField=C::BaseField>> CycleSideParams<C, Affine<G>>
{
    pub fn prove_side<R: Rng>(
        &self,
        blinded_path: Vec<Affine<G>>,
        witness: &[LevelWitnessWithBlinding<Affine<G>>],
        rng: &mut R,
    ) -> CycleSideProof<C::ScalarField, C> {
        debug_assert_eq!(blinded_path.len(), witness.len());
        let mut piop_proofs = Vec::with_capacity(witness.len());
        let mut fixed_columns_committed = Vec::with_capacity(witness.len());
        let mut polys = Vec::with_capacity(witness.len() * 9);
        let mut coords = Vec::with_capacity(witness.len() * 9);

        let plonk_prover = PlonkProver::<C::ScalarField, HidingIpa<C>, _>::init(
            self.pcs_params.ck(),
            blinded_path.clone(),
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        for (level, blinded_node) in witness.iter().zip(blinded_path.into_iter()) {
            let (fixed_columns, verifier_key) = self.commit_children(&level.level_witness.siblings, level.parent_bf);
            // debug_assert_eq!(verifier_key.fixed_columns_committed.points[0].0, *blinded_node);
            fixed_columns_committed.push(verifier_key.fixed_columns_committed);
            let piop = PiopProver::build(&self.piop_params, fixed_columns, level.level_witness.path_node_idx, level.bf);
            let blinded_node_ = <PiopProver<C::ScalarField, Affine<G>> as ProverPiop<C::ScalarField, IPACommitment<C>>>::result(&piop);
            debug_assert_eq!(blinded_node_, blinded_node);
            let (pcs_openings, piop_proof, mut transcript) = plonk_prover.reduce_to_pcs_opening(piop);
            piop_proofs.push(piop_proof);
            let PcsOpeningAt2Points {
                polys_at_zeta,
                polys_at_zeta_omega,
                zeta,
                zeta_omega,
            } = pcs_openings;

            coords.extend(vec![BTreeSet::from([zeta]); polys_at_zeta.len()]);
            polys.extend(polys_at_zeta);
            coords.extend(vec![BTreeSet::from([zeta_omega]); polys_at_zeta_omega.len()]);
            polys.extend(polys_at_zeta_omega);
        }

        let parent_bf = witness.iter().map(|level| level.parent_bf).sum();
        let todo = Coeffs(C::ScalarField::rand(rng), C::ScalarField::rand(rng));
        let pcs_proof = Shplonk::<C::ScalarField, HidingIpa<C>>::open_many(
            &self.pcs_params,
            &polys,
            &coords,
            parent_bf,
            &mut todo.clone(),
        );

        let proof = CycleSideProof {
            piop_proofs,
            pcs_proof,
            todo,
            fixed_columns_committed,
        };
        proof
    }
}