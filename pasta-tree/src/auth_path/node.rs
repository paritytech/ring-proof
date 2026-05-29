use crate::{CircuitParams, CycleSideParams2};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_std::UniformRand;
use ark_std::rand::Rng;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;

/// An element of a tree authentication path. A node on the path together with it's sibling.
/// `path_node = self.siblings[self.path_node_idx]` is the node on the path.
/// The next node on the path to the root can be computed as `parent = commit(self.siblings)`.
// TODO: the minimal witness is x-coords of the siblings, and y_i
#[derive(Clone, Debug)]
pub struct LevelWitness<G> {
    pub(crate) siblings: Vec<G>,
    pub(crate) path_node_idx: usize,
}

impl<G: AffineRepr> LevelWitness<G> {
    pub fn new(siblings: Vec<G>, path_node_idx: usize) -> Result<Self, ()> {
        debug_assert!(path_node_idx < siblings.len());
        (path_node_idx < siblings.len()).then_some(()).ok_or(())?;
        Ok(Self {
            siblings,
            path_node_idx,
        })
    }

    pub fn x_coords(&self) -> Vec<G::BaseField> {
        self.siblings.iter().map(|p| p.x()).flatten().collect()
    }

    pub fn path_node(&self) -> G {
        self.siblings[self.path_node_idx]
    }

    pub fn with_blinding(
        &self,
        self_bf: G::ScalarField,
        parent_bf: G::BaseField,
    ) -> LevelWitnessWithBlinding<G> {
        LevelWitnessWithBlinding {
            level_witness: self.clone(),
            bf: self_bf,
            parent_bf,
        }
    }

    pub fn with_random_blinding<R: Rng>(
        &self,
        parent_bf: G::BaseField,
        rng: &mut R,
    ) -> LevelWitnessWithBlinding<G> {
        self.with_blinding(G::ScalarField::rand(rng), parent_bf)
    }

    pub fn compute_parent<C, P>(&self, params: &CycleSideParams2<C, G, P>) -> Result<C::Affine, ()>
    where
        G::BaseField: PrimeField,
        C: CurveGroup<ScalarField = G::BaseField>,
        P: CircuitParams<C, G>,
    {
        self.compute_parent_with_bf(params, C::ScalarField::zero())
    }

    fn compute_parent_with_bf<C, P>(
        &self,
        params: &CycleSideParams2<C, G, P>,
        bf: C::ScalarField,
    ) -> Result<C::Affine, ()>
    where
        G::BaseField: PrimeField,
        C: CurveGroup<ScalarField = G::BaseField>,
        P: CircuitParams<C, G>,
    {
        params.commit_tree_nodes(&self.x_coords(), bf).map(|c| c.0)
    }
}

/// NB! It is not "blinded", meaning that the blinding factor hasn't been applied.
#[derive(Clone)]
pub struct LevelWitnessWithBlinding<G: AffineRepr> {
    pub(crate) level_witness: LevelWitness<G>,
    /// the verifier gets `Ci' = siblings[i] + bf.H`
    pub(crate) bf: G::ScalarField,
    /// Let `Ci = c1.G1 + ... + cm.Gm` -- the non-hiding commitment to a level.
    /// Provided that, instead, the verifier gets `Ci' = Ci + bf.H`,
    /// when opening the commitment, the prover interprets it as a hiding commitment
    /// and needs to know the parent's blinding factor to open to the same values.
    /// The root is not blinded, so `parent_bf = 0` for the level below the root.
    pub(crate) parent_bf: G::BaseField, // = C::ScalarField
}

impl<G: AffineRepr> LevelWitnessWithBlinding<G> {
    pub(crate) fn blinded_path_node(&self, ipa_pcs: &HidingIpa<G::Group>) -> Result<G, ()> {
        let blinded_path_node = ipa_pcs.reblind(
            self.level_witness.path_node(),
            G::ScalarField::zero(),
            self.bf,
        )?;
        Ok(blinded_path_node.0)
    }

    pub(crate) fn compute_parent<C, P>(
        &self,
        params: &CycleSideParams2<C, G, P>,
    ) -> Result<C::Affine, ()>
    where
        G::BaseField: PrimeField,
        C: CurveGroup<ScalarField = G::BaseField>,
        P: CircuitParams<C, G>,
    {
        self.level_witness
            .compute_parent_with_bf(params, self.parent_bf)
    }
}
