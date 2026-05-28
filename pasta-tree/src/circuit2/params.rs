use crate::LevelProof;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::circuit2::prover::PiopProver;
use crate::circuit2::verifier::PiopVerifier;
use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::FieldColumn;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::booleanity::BitColumn;
use w3f_plonk_common::gadgets::ec::AffineColumn;

/// Plonk Interactive Oracle Proofs (PIOP) parameters.
/// `max_nodes + blinding_bits = domain.capacity - 1`
#[derive(Clone)]
pub struct PiopParams<G: AffineRepr<BaseField: PrimeField>> {
    /// Domain over which the piop is represented.
    pub domain: Domain<G::BaseField>,
    pub max_nodes: usize,
    /// Number of bits used to represent a blinding factor.
    pub blinding_bits: usize,
    pub seed: G,
    /// Blinding base point.
    pub h: G,
}

impl<G: SWCurveConfig<BaseField: PrimeField>> PiopParams<SwAffine<G>> {
    pub fn prover_piop(
        &self,
        level: LevelWitnessWithBlinding<SwAffine<G>>,
    ) -> PiopProver<SwAffine<G>> {
        PiopProver::build(&self, level)
    }

    pub fn verifier_piop<C: CurveGroup<ScalarField = G::BaseField>>(
        &self,
        // re-randomized child
        child: SwAffine<G>,
        // re-randomized parent
        parent: C::Affine,
        selector: C::Affine,
        proof: LevelProof<C>,
        zeta: C::ScalarField,
    ) -> PiopVerifier<C, SwAffine<G>> {
        let domain_at_zeta = self.domain.evaluate(zeta);
        PiopVerifier::init(
            domain_at_zeta,
            WrappedAffine(parent),
            WrappedAffine(selector),
            proof.column_commitments.clone(),
            proof.columns_at_zeta.clone(),
            self.seed,
            child,
        )
    }

    // use crate::circuit::prover::PiopProver as PiopProver2;
    // pub fn prover2(&self, level: LevelWitnessWithBlinding<SwAffine<G>>) -> PiopProver2<G::BaseField, SwAffine<G>> {
    //     let piop = PiopProver2::build(&self, level);
    //     piop
    // }
}

impl<G: AffineRepr<BaseField: PrimeField>> PiopParams<G> {
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

    pub fn commit_x_coords(
        &self,
        siblings_x_coords: Vec<G::BaseField>,
    ) -> FieldColumn<G::BaseField> {
        assert!(siblings_x_coords.len() <= self.max_nodes);
        let mut x_coords = siblings_x_coords;
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

    pub fn x_coords_from_points(&self, child_nodes: Vec<G>) -> FieldColumn<G::BaseField> {
        let points = self.siblings_with_blinding(child_nodes);
        let (mut x_coords, mut y_coords): (Vec<G::BaseField>, Vec<G::BaseField>) =
            points.iter().map(|p| p.xy().unwrap()).unzip();
        let payload_len = self.domain.capacity - 1;
        assert_eq!(x_coords.len(), payload_len);
        // x_coords.push(G::BaseField::one());
        // assert_eq!(x_coords.len(), self.domain.capacity);

        // zk_rows
        x_coords.resize(self.domain.domain_size(), G::BaseField::zero());
        y_coords.resize(self.domain.domain_size(), G::BaseField::zero());
        self.domain.domains.column_from_evals(x_coords, payload_len)
    }

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

    pub fn select_part(&self) -> FieldColumn<G::BaseField> {
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
