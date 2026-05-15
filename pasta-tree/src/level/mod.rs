mod prover;
mod verifier;

use crate::ipa_hiding::HidingIpa;
use crate::Coeffs;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, Zero};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use std::marker::PhantomData;
use w3f_pcs::pcs::{PcsParams, PCS};
use w3f_pcs::shplonk::AggregateProof;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::PiopProof;
use w3f_ring_proof::piop::{FixedColumns, RingCommitments, RingEvaluations};
use w3f_ring_proof::{FixedColumnsCommitted, PiopParams, VerifierKey};

struct CycleSideParams<C: CurveGroup, G: SWCurveConfig<BaseField=C::ScalarField>>
{
    pcs_params: HidingIpa<C>,
    piop_params: PiopParams<C::ScalarField, G>,
}

struct CycleParams<C: SWCurveConfig, G: SWCurveConfig<BaseField=C::ScalarField, ScalarField=C::BaseField>>
{
    c0_params: CycleSideParams<Projective<C>, G>,
    c1_params: CycleSideParams<Projective<G>, C>,
}

impl<C: SWCurveConfig, G: SWCurveConfig<BaseField=C::ScalarField, ScalarField=C::BaseField>> CycleParams<C, G> where C::BaseField: PrimeField {
    pub fn setup<R: Rng>(rng: &mut R, domain_size: usize) -> Self {
        let setup_degree = 3 * domain_size;
        let pcs_params_0 = HidingIpa::<Projective<C>>::setup(setup_degree, rng);
        let pcs_params_1 = HidingIpa::<Projective<G>>::setup(setup_degree, rng);
        let domain_0 = Domain::<C::ScalarField>::new(domain_size, true);
        let domain_1 = Domain::<G::ScalarField>::new(domain_size, true);
        let seed_0 = Affine::<G>::rand(rng);
        let padding_0 = Affine::<G>::rand(rng);
        let piop_params_0 = PiopParams::<C::ScalarField, G>::setup(domain_0, pcs_params_1.h, seed_0, padding_0);
        let seed_1 = Affine::<C>::rand(rng);
        let padding_1 = Affine::<C>::rand(rng);
        let piop_params_1 = PiopParams::<G::ScalarField, C>::setup(domain_1, pcs_params_0.h, seed_1, padding_1);
        Self {
            c0_params: CycleSideParams { pcs_params: pcs_params_0, piop_params: piop_params_0 },
            c1_params: CycleSideParams { pcs_params: pcs_params_1, piop_params: piop_params_1 },
        }
    }
}

struct LevelProof<C: CurveGroup> {
    piop_proof: PiopProof<C::ScalarField, <HidingIpa<C> as PCS<C::ScalarField>>::C, RingCommitments<C::ScalarField, <HidingIpa<C> as PCS<C::ScalarField>>::C>, RingEvaluations<C::ScalarField>>,
    pcs_opening_proof: AggregateProof<C::ScalarField, HidingIpa<C>>,
    todo: Coeffs<C::ScalarField>,
}

type IPACommitment<C> = <HidingIpa<C> as PCS<<C as PrimeGroup>::ScalarField>>::C;

impl<C: CurveGroup, G: SWCurveConfig<BaseField=C::ScalarField>> CycleSideParams<C, G> {
    pub fn setup<R: Rng>(rng: &mut R, domain_size: usize) -> Self {
        let setup_degree = 3 * domain_size;
        let pcs_params = HidingIpa::<C>::setup(setup_degree, rng);
        let domain = Domain::new(domain_size, true);
        let h = Affine::<G>::rand(rng);
        let seed = Affine::<G>::rand(rng);
        let padding = Affine::<G>::rand(rng);
        let piop_params = PiopParams::setup(domain, h, seed, padding);
        Self {
            pcs_params,
            piop_params,
        }
    }

    pub fn commit_child_nodes(&self, nodes: &[Affine<G>], r: C::ScalarField) -> (
        FixedColumns<G::BaseField, Affine<G>>,
        VerifierKey<G::BaseField, HidingIpa<C>>
    ) {
        let fixed_columns = self.piop_params.fixed_columns(&nodes);
        let xs = fixed_columns.points.xs.as_poly();
        let ys = fixed_columns.points.ys.as_poly();
        let fixed_columns_committed = FixedColumnsCommitted {
            points: [
                self.pcs_params.commit_hiding(xs, r).unwrap(),
                self.pcs_params.commit_hiding(ys, C::ScalarField::zero()).unwrap(),
            ],
            ring_selector: self.pcs_params.commit_hiding(fixed_columns.ring_selector.as_poly(), C::ScalarField::zero()).unwrap(),
            phantom: PhantomData,
        };
        let verifier_key = VerifierKey {
            pcs_raw_vk: self.pcs_params.raw_vk(),
            fixed_columns_committed,
        };
        (fixed_columns, verifier_key)
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_ff::{Field, Zero};
    use ark_pallas::PallasConfig;
    use ark_poly::DenseUVPolynomial;
    use ark_std::rand::Rng;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use ark_vesta::VestaConfig;
    use w3f_pcs::pcs::PCS;
    use w3f_plonk_common::test_helpers::random_vec;

    use crate::level::{CycleParams, CycleSideParams};
    use crate::level::prover::LevelWitness;

    fn random_node<C: CurveGroup, G: SWCurveConfig<BaseField=C::ScalarField>, R: Rng>(params: &CycleSideParams<C, G>, child: Option<Affine<G>>, rng: &mut R) -> (C::Affine, LevelWitness<G>)
    {
        let capacity = params.piop_params.keyset_part_size;
        let mut children = random_vec::<Affine<G>, _>(capacity, rng);
        let i = rng.gen_range(0..capacity);
        if child.is_some() {
            children[i] = child.unwrap();
        }
        let fixed_columns = params.piop_params.fixed_columns(&children);
        let children_xs = fixed_columns.points.xs.as_poly();
        let parent = params.pcs_params.commit_hiding(children_xs, C::ScalarField::zero());
        let parent = parent.unwrap().0;
        let witness = LevelWitness {
            siblings: children,
            i,
            child_r: G::ScalarField::rand(rng),
            parent_r: C::ScalarField::zero(),
        };
        (parent, witness)
    }

    fn _test_level_proof<F0, F1, C0, C1>()
    where
        F0: PrimeField,
        F1: PrimeField,
        C0: SWCurveConfig<BaseField=F1, ScalarField=F0>,
        C1: SWCurveConfig<BaseField=F0, ScalarField=F1>,
    {
        let rng = &mut test_rng();

        // setup
        let domain_size = 2usize.pow(9);
        let CycleParams {
            c0_params,
            c1_params,
        } = CycleParams::<C0, C1>::setup(rng, domain_size);

        let (l1_node, mut l2_nodes) = random_node(&c1_params, None, rng);
        let (l0_node, l1_nodes) = random_node(&c0_params, Some(l1_node), rng);

        let (_, l1_vk) = c0_params.commit_child_nodes(l1_nodes.siblings.as_slice(), F0::zero());

        let root_fc = l1_vk.fixed_columns_committed;
        let leaf = l2_nodes.siblings[l2_nodes.i];

        let capacity = c0_params.piop_params.keyset_part_size;
        let t_prove = start_timer!(|| format!("Proving 1st level of a curve tree, domain_size={domain_size}, capacity={capacity}"));
        let (l1_node_blinded, l1_proof) = c0_params.prove_level(&l1_nodes, rng);
        end_timer!(t_prove);

        let t_verify = start_timer!(|| format!("Verifying a single-level proof"));
        assert!(c0_params.verify_level(root_fc, l1_node_blinded, l1_proof));
        end_timer!(t_verify);

        let l2_nodes_parent_r = l1_nodes.child_r;
        let (l2_column, l2_vk) = c1_params.commit_child_nodes(l2_nodes.siblings.as_slice(), l2_nodes_parent_r);
        let l1_node_fc = l2_vk.fixed_columns_committed;
        assert_eq!(l1_node_fc.points[0].0, l1_node_blinded);

        l2_nodes.parent_r = l2_nodes_parent_r;
        let t_prove = start_timer!(|| format!("Proving 2nd level of a curve tree, domain_size={domain_size}, capacity={capacity}"));
        let (blinded_leaf, l2_proof) = c1_params.prove_level(&l2_nodes, rng);
        end_timer!(t_prove);

        let t_verify = start_timer!(|| format!("Verifying a single-level proof"));
        assert!(c1_params.verify_level(l1_node_fc, blinded_leaf, l2_proof));
        end_timer!(t_verify);
    }

    // cargo test test_level_proof --release --features="print-trace" -- --show-output
    #[test]
    fn test_level_proof() {
        _test_level_proof::<_, _, PallasConfig, VestaConfig>()
    }
}