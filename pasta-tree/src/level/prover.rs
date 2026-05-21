use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::level::LevelProof;
use crate::{Coeffs, CycleSideParams, IPACommitment};
use ark_ec::CurveGroup;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::Zero;
use ark_poly::Polynomial;
use ark_std::rand::Rng;
use ark_std::{UniformRand, end_timer, start_timer};
use std::collections::BTreeSet;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::piop::ProverPiop;
use w3f_plonk_common::prover::{PcsOpeningAt2Points, PlonkProver};
use w3f_ring_proof::ArkTranscript;
use w3f_ring_proof::piop::prover::PiopProver;

impl<C: CurveGroup, G: SWCurveConfig<BaseField = C::ScalarField, ScalarField = C::BaseField>>
    CycleSideParams<C, Affine<G>>
{
    pub fn prove_level<R: Rng>(
        &self,
        witness: &LevelWitnessWithBlinding<Affine<G>>,
        rng: &mut R,
    ) -> (Affine<G>, LevelProof<C>) {
        let (fixed_columns, verifier_key) =
            self.commit_children(&witness.level_witness.siblings, witness.parent_bf);
        let piop = PiopProver::build(
            &self.piop_params,
            fixed_columns,
            witness.level_witness.path_node_idx,
            witness.bf,
        );
        let blinded_node = <PiopProver<C::ScalarField, Affine<G>> as ProverPiop<
            C::ScalarField,
            IPACommitment<C>,
        >>::result(&piop);
        // let blinded_parent = verifier_key.fixed_columns_committed.points[0].clone();
        let plonk_prover = PlonkProver::<C::ScalarField, HidingIpa<C>, _>::init(
            self.pcs_params.ck(),
            verifier_key,
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );
        let (pcs_openings, piop_proof, _transcript) = plonk_prover.reduce_to_pcs_opening(piop);
        let PcsOpeningAt2Points {
            polys_at_zeta,
            polys_at_zeta_omega,
            zeta,
            zeta_omega,
        } = pcs_openings;

        let mut coord_vecs = vec![vec![zeta]; polys_at_zeta.len()];
        coord_vecs.push(vec![zeta_omega]);
        let polys = [polys_at_zeta, polys_at_zeta_omega].concat();
        let mut bfs = vec![C::ScalarField::zero(); polys.len()];
        bfs[0] = witness.parent_bf;

        let coord_sets: Vec<BTreeSet<C::ScalarField>> = coord_vecs
            .iter()
            .cloned()
            .map(BTreeSet::from_iter)
            .collect();

        let todo = Coeffs(C::ScalarField::rand(rng), C::ScalarField::rand(rng));
        let t_open = start_timer!(|| format!(
            "Opening IPA ring-proof with shplonk, {} polys, max_degree = {}",
            polys.len(),
            polys[polys.len() - 2].degree() // the quotient
        ));
        let pcs_opening_proof = Shplonk::<C::ScalarField, HidingIpa<C>>::open_many_hiding(
            &self.pcs_params,
            &polys,
            &bfs,
            &coord_sets,
            &mut todo.clone(),
            rng,
        );
        end_timer!(t_open);

        let proof = LevelProof {
            piop_proof,
            pcs_opening_proof,
            todo,
        };
        (blinded_node, proof)
    }
}
