use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::{CycleParams, CycleSide};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

pub struct AuthenticationPathWithBlinding<C0: CurveGroup, C1: CurveGroup> {
    pub(crate) c0_path: Vec<LevelWitnessWithBlinding<C0::Affine>>,
    pub(crate) c1_path: Vec<LevelWitnessWithBlinding<C1::Affine>>,
}

#[derive(Clone, Debug)]
pub struct BlindedAuthenticationPath<C0: CurveGroup, C1: CurveGroup> {
    pub(crate) c0_path: Vec<C0::Affine>,
    pub(crate) c1_path: Vec<C1::Affine>,
}

impl<F0, F1, C0, C1> AuthenticationPathWithBlinding<C0, C1>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: CurveGroup<BaseField = F1, ScalarField = F0>,
    C1: CurveGroup<BaseField = F0, ScalarField = F1>,
{
    pub(crate) fn apply_bfs(
        &self,
        params: &CycleParams<C0, C1>,
    ) -> BlindedAuthenticationPath<C0, C1> {
        let c0_path = self
            .c0_path
            .iter()
            .map(|c0_level| {
                c0_level
                    .blinded_path_node(&params.c0_params.pcs_params)
                    .unwrap()
            })
            .collect();
        let c1_path = self
            .c1_path
            .iter()
            .map(|c1_level| {
                c1_level
                    .blinded_path_node(&params.c1_params.pcs_params)
                    .unwrap()
            })
            .collect();
        BlindedAuthenticationPath { c0_path, c1_path }
    }
    pub fn compute_root(
        &self,
        params: &CycleParams<C0, C1>,
    ) -> Result<CycleSide<C0::Affine, C1::Affine>, ()> {
        let mut c0_path_iter = self.c0_path.iter();
        let c0_nodes = c0_path_iter.next().unwrap();
        let mut parent_on_c1 = c0_nodes.compute_parent(&params.c1_params)?;
        for c1_nodes in self.c1_path.iter() {
            let next_c1_path_node = c1_nodes.blinded_path_node(&params.c1_params.pcs_params)?;
            debug_assert_eq!(parent_on_c1, next_c1_path_node);
            (parent_on_c1 == next_c1_path_node)
                .then_some(())
                .ok_or(())?;
            let parent_on_c0 = c1_nodes.compute_parent(&params.c0_params)?;
            match c0_path_iter.next() {
                Some(c0_nodes) => {
                    let next_c0_path_node =
                        c0_nodes.blinded_path_node(&params.c0_params.pcs_params)?;
                    debug_assert_eq!(parent_on_c0, next_c0_path_node);
                    (parent_on_c0 == next_c0_path_node)
                        .then_some(())
                        .ok_or(())?;
                    parent_on_c1 = c0_nodes.compute_parent(&params.c1_params)?;
                }
                None => return Ok(CycleSide::C0(parent_on_c0)),
            }
        }
        Ok(CycleSide::C1(parent_on_c1))
    }
}
