use crate::CycleSideParams;
use crate::ipa_hiding::HidingIpa;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};

/// An element of a tree authentication path. A node on the path together with it's sibling.
/// `path_node = self.siblings[self.path_node_idx]` is the node on the path.
/// The next node on the path to the root can be computed as `parent = commit(self.siblings)`.
// TODO: the minimal witness is x-coords of the siblings, and y_i
#[derive(Clone, Debug)]
pub struct LevelWitness<G> {
    siblings: Vec<G>,
    path_node_idx: usize,
}

impl<G: AffineRepr> LevelWitness<G> {
    pub(crate) fn new(siblings: Vec<G>, path_node_idx: usize) -> Result<Self, ()> {
        debug_assert!(path_node_idx < siblings.len());
        (path_node_idx < siblings.len()).ok_or(())?;
        Ok(Self {
            siblings,
            path_node_idx,
        })
    }

    fn x_coords(&self) -> Vec<G::BaseField> {
        self.siblings.iter().map(|p| p.x()).flatten().collect()
    }

    pub(crate) fn path_node(&self) -> G {
        self.siblings[self.path_node_idx]
    }

    pub(crate) fn with_blinding(
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

    pub(crate) fn compute_parent<C: CurveGroup<ScalarField = G::BaseField>>(
        &self,
        params: &CycleSideParams<C>,
    ) -> Result<C, ()>
    where
        G::BaseField: PrimeField,
    {
        self.compute_parent_with_bf(params, C::ScalarField::zero())
    }

    fn compute_parent_with_bf<C: CurveGroup<ScalarField = G::BaseField>>(
        &self,
        params: &CycleSideParams<C>,
        bf: C::ScalarField,
    ) -> Result<C, ()>
    where
        G::BaseField: PrimeField,
    {
        params.commit_node(self.x_coords(), bf)
    }
}

/// NB! It is not "blinded", meaning that the blinding factor hasn't been applied.
pub struct LevelWitnessWithBlinding<G: AffineRepr> {
    level_witness: LevelWitness<G>,
    /// the verifier gets `Ci' = siblings[i] + bf.H`
    bf: G::ScalarField,
    /// Let `Ci = c1.G1 + ... + cm.Gm` -- the non-hiding commitment to a level.
    /// Provided that, instead, the verifier gets `Ci' = Ci + bf.H`,
    /// when opening the commitment, the prover interprets it as a hiding commitment
    /// and needs to know the parent's blinding factor to open to the same values.
    /// The root is not blinded, so `parent_bf = 0` for the level below the root.
    parent_bf: G::BaseField, // = C::ScalarField
}

impl<G: AffineRepr> LevelWitnessWithBlinding<G> {
    pub(crate) fn blinded_path_node(&self, ipa_pcs: &HidingIpa<G::Group>) -> Result<G, ()> {
        Ok(ipa_pcs
            .reblind(
                self.level_witness.path_node(),
                G::ScalarField::zero(),
                self.bf,
            )?
            .0)
    }

    pub(crate) fn compute_parent<C: CurveGroup<ScalarField = G::BaseField>>(
        &self,
        params: &CycleSideParams<C>,
    ) -> Result<C, ()>
    where
        G::BaseField: PrimeField,
    {
        self.level_witness
            .compute_parent_with_bf(params, self.parent_bf)
    }
}
