use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::{CycleParams, CycleSide};

pub struct AuthenticationPathWithBlinding<C0: CurveGroup, C1: CurveGroup> {
    pub(crate) c0_path: Vec<LevelWitnessWithBlinding<C0::Affine>>,
    pub(crate) c1_path: Vec<LevelWitnessWithBlinding<C1::Affine>>,
}

impl<F0, F1, C0, C1> AuthenticationPathWithBlinding<C0, C1>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: CurveGroup<BaseField=F1, ScalarField=F0>,
    C1: CurveGroup<BaseField=F0, ScalarField=F1>,
{
    pub(crate) fn compute_root(&self, params: &CycleParams<C0, C1>) -> Result<CycleSide<C0::Affine, C1::Affine>, ()> {
        let mut path_0_iter = self.c0_path.iter();
        let c0_nodes = path_0_iter.next().unwrap();
        let mut parent_on_c1 = c0_nodes.compute_parent(&params.c1_params).unwrap().into_affine();
        for c1_nodes in self.c1_path.iter() {
            let next_c1_path_node = c1_nodes.blinded_path_node(&params.c1_params.ipa_pcs)?;
            debug_assert_eq!(parent_on_c1, next_c1_path_node);
            (parent_on_c1 == next_c1_path_node).ok_or(())?;
            let parent_on_c0 = c1_nodes.compute_parent(&params.c0_params).unwrap().into_affine();
            match path_0_iter.next() {
                Some(c0_nodes) => {
                    let next_c0_path_node = c0_nodes.blinded_path_node(&params.c0_params.ipa_pcs)?;
                    debug_assert_eq!(parent_on_c0, next_c0_path_node);
                    (parent_on_c0 == next_c0_path_node).ok_or(())?;
                    parent_on_c1 = c0_nodes.compute_parent(&params.c1_params).unwrap().into_affine();
                }
                None => return Ok(CycleSide::C0(parent_on_c0))
            }
        }
        Ok(CycleSide::C1(parent_on_c1))
    }
}