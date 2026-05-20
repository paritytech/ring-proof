use crate::auth_path::blinded::AuthenticationPathWithBlinding;
use crate::auth_path::node::LevelWitness;
use crate::{CycleParams, CycleSide};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::Rng;

/// A non-hiding authentication path from a leaf to the root, split between the curves of the cycle.
/// For each tree level (excluding the root), the corresponding element of the authentication path (`LevelWitness`)
/// contains the root-path node at that level, together with all its siblings.
/// That allows to recompute the parent -- the path node at the *previous* level, up to the root.
/// `path_0[0]` contains the leaf (with its siblings).
/// `commit(path_0[k].siblings) = path_1[k].siblings[path_1[k].i]`, if `path_1[k]` exists,
/// otherwise it's the root.
pub struct AuthenticationPath<C0: CurveGroup, C1: CurveGroup> {
    /// Nodes on the `C0` curve.
    pub c0_path: Vec<LevelWitness<C0::Affine>>,
    /// Nodes on the `C1` curve.
    pub c1_path: Vec<LevelWitness<C1::Affine>>,
}

impl<F0, F1, C0, C1> AuthenticationPath<C0, C1>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: CurveGroup<BaseField = F1, ScalarField = F0>,
    C1: CurveGroup<BaseField = F0, ScalarField = F1>,
{
    pub fn with_blinding<R: Rng>(&self, rng: &mut R) -> AuthenticationPathWithBlinding<C0, C1> {
        let mut path_0 = Vec::with_capacity(self.c0_path.len());
        let mut path_1 = Vec::with_capacity(self.c1_path.len());

        let mut c0_path_iter = self.c0_path.iter();
        let mut c0_nodes = c0_path_iter.next().unwrap(); // shouldn't be empty
        let mut c0_bf = C0::ScalarField::rand(rng);
        for c1_nodes in self.c1_path.iter() {
            let c1_bf = C1::ScalarField::rand(rng);
            path_0.push(c0_nodes.with_blinding(c0_bf, c1_bf));
            match c0_path_iter.next() {
                Some(c0_nodes_) => {
                    c0_nodes = c0_nodes_;
                    c0_bf = C0::ScalarField::rand(rng);
                    path_1.push(c1_nodes.with_blinding(c1_bf, c0_bf));
                }
                None => {
                    // then the parent of `c1_nodes` is the root
                    c0_bf = C0::ScalarField::zero(); // `c0_bf = 0` indicates this case
                    let root_bf = c0_bf;
                    path_1.push(c1_nodes.with_blinding(c1_bf, root_bf));
                }
            }
        }
        if !c0_bf.is_zero() {
            // then `c0_nodes` are the level below the root
            let root_bf = C1::ScalarField::zero();
            path_0.push(c0_nodes.with_blinding(c0_bf, root_bf));
        }

        debug_assert_eq!(path_0.len(), self.c0_path.len());
        debug_assert_eq!(path_1.len(), self.c1_path.len());

        AuthenticationPathWithBlinding {
            c0_path: path_0,
            c1_path: path_1,
        }
    }

    fn get_leaf(&self) -> C0::Affine {
        self.c0_path[0].path_node()
    }

    fn compute_root(
        &self,
        params: &CycleParams<C0, C1>,
    ) -> Result<CycleSide<C0::Affine, C1::Affine>, ()> {
        let mut c0_path_iter = self.c0_path.iter();
        let c0_nodes = c0_path_iter.next().unwrap(); // shouldn't be empty
        let mut parent_on_c1 = c0_nodes.compute_parent(&params.c1_params)?;
        for c1_nodes in self.c1_path.iter() {
            debug_assert_eq!(parent_on_c1, c1_nodes.path_node());
            (parent_on_c1 == c1_nodes.path_node()).ok_or(())?;
            let parent_on_c0 = c1_nodes.compute_parent(&params.c0_params)?;
            match c0_path_iter.next() {
                Some(c0_nodes) => {
                    debug_assert_eq!(parent_on_c0, c0_nodes.path_node());
                    (parent_on_c0 == c0_nodes.path_node()).ok_or(())?;
                    parent_on_c1 = c0_nodes.compute_parent(&params.c1_params)?;
                }
                None => return Ok(CycleSide::C0(parent_on_c0)),
            }
        }
        Ok(CycleSide::C1(parent_on_c1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{random_nodes, random_path};
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_auth_path() {
        let rng = &mut test_rng();

        let domain_size = 2usize.pow(9);
        let params =
            CycleParams::<ark_pallas::Projective, ark_vesta::Projective>::setup(domain_size, rng);

        let (leaf, path, root) = random_path(&params, 2, rng);

        assert_eq!(path.get_leaf(), leaf);
        assert_eq!(path.compute_root(&params).unwrap(), root);

        let path_with_bfs = path.with_blinding(rng);
        assert_eq!(path_with_bfs.compute_root(&params).unwrap(), root);
    }
}
