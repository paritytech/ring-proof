use crate::CircuitParams;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::circuit_tall::prover::PiopProver;
use crate::circuit_tall::verifier::PiopVerifier;
// use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_ff::{FftField, One};
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::FieldColumn;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::booleanity::BitColumn;
use w3f_plonk_common::gadgets::ec::AffineColumn;

// `max_nodes + blinding_bits = domain.capacity - 1`
// where `1` acounts for the `seed` point.
/// Circuit parameters
#[derive(Clone)]
pub struct PiopParams<G: AffineRepr<BaseField: FftField>> {
    /// Domain over which the circuit is represented.
    pub domain: Domain<G::BaseField>,
    /// Maximal number of children per tree node.
    pub max_nodes: usize,
    /// Number of bits used to represent a blinding factor.
    pub blinding_bits: usize,
    /// Point that initializes the EC addition gadget accumulator.
    pub seed: G,
    /// Pedersen blinding base point.
    pub h: G,
}

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> CircuitParams<C, G>
    for PiopParams<G>
{
    type Commitments = crate::circuit_tall::ProofComms<C>;
    type Evaluations = crate::circuit_tall::ProofEvals<C::ScalarField>;
    type ProverCircuit = PiopProver<G>;
    type VerifierCircuit = PiopVerifier<C, G>;

    fn prover_circuit(&self, level: LevelWitnessWithBlinding<G>) -> Self::ProverCircuit {
        PiopProver::build(&self, level)
    }

    fn verifier_circuit(
        &self,
        instance: (G, C::Affine),
        fixed_cols: &[WrappedAffine<C>],
        cols: Self::Commitments,
        evals: Self::Evaluations,
        zeta: C::ScalarField,
    ) -> Self::VerifierCircuit {
        assert_eq!(fixed_cols.len(), 1, "Expected 1 fixed columns");
        let selector = fixed_cols[0].clone();
        let domain_at_zeta = self.domain.evaluate(zeta);
        let (child, x_parent) = instance;
        PiopVerifier::init(
            domain_at_zeta,
            WrappedAffine(x_parent),
            selector,
            cols,
            evals,
            self.seed,
            child,
        )
    }

    fn fixed_columns(&self) -> Vec<FieldColumn<G::BaseField>> {
        vec![self.select_part()]
    }

    fn tree_nodes_column(&self, children_x_coords: &[G::BaseField]) -> FieldColumn<G::BaseField> {
        assert!(children_x_coords.len() <= self.max_nodes);
        let mut x_coords = children_x_coords.to_vec();
        // padding
        x_coords.resize(self.max_nodes, G::BaseField::zero());
        // `powers_of_h` x-coords
        let powers_of_h = self.power_of_h();
        assert_eq!(powers_of_h.len(), self.blinding_bits);
        let powers_of_h_xs = powers_of_h.into_iter().filter_map(|p| p.x());
        x_coords.extend(powers_of_h_xs);
        let payload_len = self.domain.capacity - 1;
        assert_eq!(x_coords.len(), payload_len);
        // x_coords.push(G::BaseField::one());
        // assert_eq!(x_coords.len(), self.domain.capacity);

        // zk_rows
        x_coords.resize(self.domain.domain_size(), G::BaseField::zero());
        self.domain.domains.column_from_evals(x_coords, payload_len)
    }

    fn max_children(&self) -> usize {
        self.max_nodes
    }

    #[cfg(test)]
    fn setup(domain: Domain<G::BaseField>, h: G, seed: G) -> Self {
        Self::setup(domain, h, seed)
    }
}

impl<G: AffineRepr<BaseField: FftField>> PiopParams<G> {
    pub fn setup(domain: Domain<G::BaseField>, h: G, seed: G) -> Self {
        assert!(domain.domain_size() > 256);
        let actual_capacity = domain.capacity - 1;
        let scalar_size = Domain::<G::BaseField>::new(256, domain.is_hiding()).capacity - 1;
        let blinding_bits =
            ark_std::cmp::min(G::ScalarField::MODULUS_BIT_SIZE as usize, scalar_size);
        let max_nodes = actual_capacity - blinding_bits;
        Self {
            domain,
            max_nodes,
            blinding_bits,
            seed,
            h,
        }
    }

    // fn x_coords_from_points(&self, child_nodes: Vec<G>) -> FieldColumn<G::BaseField> {
    //     let points = self.siblings_with_blinding(child_nodes);
    //     let (mut x_coords, mut y_coords): (Vec<G::BaseField>, Vec<G::BaseField>) =
    //         points.iter().map(|p| p.xy().unwrap()).unzip();
    //     let payload_len = self.domain.capacity - 1;
    //     assert_eq!(x_coords.len(), payload_len);
    //     // x_coords.push(G::BaseField::one());
    //     // assert_eq!(x_coords.len(), self.domain.capacity);
    //
    //     // zk_rows
    //     x_coords.resize(self.domain.domain_size(), G::BaseField::zero());
    //     y_coords.resize(self.domain.domain_size(), G::BaseField::zero());
    //     self.domain.domains.column_from_evals(x_coords, payload_len)
    // }

    pub fn points_column(&self, child_nodes: Vec<G>) -> AffineColumn<G::BaseField, G> {
        let points = self.siblings_with_blinding(child_nodes);
        assert_eq!(points.len(), self.domain.capacity - 1);
        AffineColumn::public_column(points, &self.domain)
    }

    fn siblings_with_blinding(&self, siblings: Vec<G>) -> Vec<G> {
        assert!(siblings.len() <= self.max_nodes);
        let mut points = siblings;
        points.resize(self.max_nodes, G::ZERO); // padding
        points.extend(self.power_of_h()); // powers of `H`
        points
    }

    pub fn bits_column(&self, node_index: usize, bf: G::ScalarField) -> BitColumn<G::BaseField> {
        let mut bits = vec![false; self.max_nodes];
        assert!(node_index < self.max_nodes); // allows to select a padding node
        bits[node_index] = true;
        bits.extend(self.scalar_part(bf));
        BitColumn::init(bits, &self.domain)
    }

    pub(super) fn select_part(&self) -> FieldColumn<G::BaseField> {
        let selector = [
            vec![G::BaseField::one(); self.max_nodes],
            vec![G::BaseField::zero(); self.blinding_bits],
        ]
        .concat();
        self.domain.public_column(selector)
    }

    fn power_of_h(&self) -> Vec<G> {
        let mut h = self.h.into_group();
        let mut res = Vec::with_capacity(self.blinding_bits);
        res.push(h);
        for _ in 1..self.blinding_bits {
            h.double_in_place();
            res.push(h);
        }
        CurveGroup::normalize_batch(&res)
    }

    fn scalar_part(&self, e: G::ScalarField) -> Vec<bool> {
        let bits_with_trailing_zeroes = e.into_bigint().to_bits_le();
        let significant_bits = &bits_with_trailing_zeroes[..self.blinding_bits];
        significant_bits.to_vec()
    }
}

#[cfg(test)]
mod tests {}
