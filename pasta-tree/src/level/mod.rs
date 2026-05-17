mod prover;
mod verifier;

use crate::ipa_hiding::HidingIpa;
use crate::Coeffs;
use ark_ec::{CurveGroup, PrimeGroup};
use w3f_pcs::pcs::PCS;
use w3f_pcs::shplonk::AggregateProof;
use w3f_plonk_common::PiopProof;
use w3f_ring_proof::piop::{RingCommitments, RingEvaluations};


pub struct LevelProof<C: CurveGroup> {
    piop_proof: PiopProof<
        C::ScalarField,
        <HidingIpa<C> as PCS<C::ScalarField>>::C,
        RingCommitments<C::ScalarField, <HidingIpa<C> as PCS<C::ScalarField>>::C>,
        RingEvaluations<C::ScalarField>,
    >,
    pcs_opening_proof: AggregateProof<C::ScalarField, HidingIpa<C>>,
    todo: Coeffs<C::ScalarField>,
}

type IPACommitment<C> = <HidingIpa<C> as PCS<<C as PrimeGroup>::ScalarField>>::C;


#[cfg(test)]
mod tests {
    use crate::auth_path::node::LevelWitness;
    use crate::CycleParams;
    use crate::CycleSideParams;
    use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_pallas::PallasConfig;
    use ark_std::rand::Rng;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use ark_vesta::VestaConfig;
    use w3f_plonk_common::test_helpers::random_vec;
    use crate::tests::random_node;

    fn _test_level_proof<F0, F1, C0, C1>()
    where
        F0: PrimeField,
        F1: PrimeField,
        C0: SWCurveConfig<BaseField = F1, ScalarField = F0>,
        C1: SWCurveConfig<BaseField = F0, ScalarField = F1>,
    {
        let rng = &mut test_rng();

        let domain_size = 2usize.pow(9);
        let CycleParams {
            c0_params,
            c1_params,
        } = CycleParams::<Projective<C0>, Projective<C1>>::setup(domain_size, rng);

        let leaf = Affine::<C0>::rand(rng);
        let (l1_node, mut l2_nodes) = random_node(&c1_params, leaf, rng);
        let (root, l1_nodes) = random_node(&c0_params, l1_node, rng);

        let (_, l1_vk) = c0_params.commit_children(l1_nodes.siblings.as_slice(), F0::zero());
        let root_fc = l1_vk.fixed_columns_committed;

        let capacity = c0_params.piop_params.keyset_part_size;
        let l1_nodes_with_bf = l1_nodes.with_random_blinding(F0::zero(), rng);
        let t_prove = start_timer!(|| format!(
            "Proving 1st level of a curve tree, domain_size={domain_size}, capacity={capacity}"
        ));
        let (l1_node_blinded, l1_proof) = c0_params.prove_level(&l1_nodes_with_bf, rng);
        end_timer!(t_prove);

        let t_verify = start_timer!(|| format!("Verifying a single-level proof"));
        assert!(c0_params.verify_level(root_fc, l1_node_blinded, l1_proof));
        end_timer!(t_verify);

        let capacity = c1_params.piop_params.keyset_part_size;

        let (_, l2_vk) = c1_params.commit_children(l2_nodes.siblings.as_slice(), l1_nodes_with_bf.bf);
        let l1_node_fc = l2_vk.fixed_columns_committed;
        assert_eq!(l1_node_fc.points[0].0, l1_node_blinded);

        let l2_nodes_with_bf = l2_nodes.with_random_blinding(l1_nodes_with_bf.bf, rng);
        let t_prove = start_timer!(|| format!(
            "Proving 2nd level of a curve tree, domain_size={domain_size}, capacity={capacity}"
        ));
        let (blinded_leaf, l2_proof) = c1_params.prove_level(&l2_nodes_with_bf, rng);
        end_timer!(t_prove);

        let t_verify = start_timer!(|| format!("Verifying a single-level proof"));
        assert!(c1_params.verify_level(l1_node_fc, blinded_leaf, l2_proof));
        end_timer!(t_verify);
    }

    // cargo test test_level_proof --release --features="print-trace" -- --show-output
    // cargo test test_level_proof --release --features="print-trace parallel" -- --show-output
    #[test]
    fn test_level_proof() {
        _test_level_proof::<_, _, PallasConfig, VestaConfig>()
    }
}
