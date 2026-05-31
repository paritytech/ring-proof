use crate::auth_path::blinded::BlindedAuthenticationPath;
use crate::{CircuitParams, CycleParams, CycleSideParams};
use crate::{CurveTreeProof, CycleSideProof};
use ark_ec::{AffineRepr, CurveGroup};
// use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use crate::ArkTranscript;
use ark_ff::PrimeField;
use w3f_pcs::pcs::PcsParams;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::Shplonk;
use w3f_plonk_common::piop::VerifierPiop;
use w3f_plonk_common::verifier::{PcsOpeningAt2Points, PlonkVerifier};

impl<C0, C1, P0, P1> CycleParams<C0, C1, P0, P1>
where
    C0: CurveGroup<BaseField: PrimeField>,
    C1: CurveGroup<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
    P0: CircuitParams<C0, C1::Affine>,
    P1: CircuitParams<C1, C0::Affine>,
{
    pub fn verify(
        &self,
        auth_path: BlindedAuthenticationPath<C0, C1>,
        proof: CurveTreeProof<C0, C1, P0, P1>,
        root: C0::Affine,
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
}

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>, P: CircuitParams<C, G>>
    CycleSideParams<C, G, P>
{
    pub fn verify_side(
        &self,
        // selected re-randomized children
        children: Vec<G>,
        // parents, re-randomized at the previous step
        parents: Vec<C::Affine>,
        side_proof: CycleSideProof<C, G, P>,
    ) -> bool {
        // let mut s = std::any::type_name::<C>();
        // s = &s[65..s.len()];
        // println!("\n\nverifier {s}\nchildren={children:?}\nparents={parents:?}\n");

        let plonk_verifier: PlonkVerifier<C::ScalarField, HidingIpa<C>, _> = PlonkVerifier::init(
            self.pcs_params.vk(),
            &(),
            ArkTranscript::new(b"pasta-tree-level-proof"),
        );

        let n_polys = P::VerifierCircuit::N_COLUMNS + 2; // plus the quotient and the linearization polys
        let mut polys = Vec::with_capacity(side_proof.piop_proofs.len() * n_polys);
        let mut coords = Vec::with_capacity(side_proof.piop_proofs.len() * n_polys);
        let mut vals = Vec::with_capacity(side_proof.piop_proofs.len() * n_polys);

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
                // '1' accounts for the quotient polynomial that is aggregated together with the columns
                P::VerifierCircuit::N_COLUMNS + 1,
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
