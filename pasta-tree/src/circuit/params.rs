use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_std::{vec, vec::Vec};

use w3f_plonk_common::FieldColumn;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::booleanity::BitColumn;
use w3f_plonk_common::gadgets::ec::AffineColumn;

/// Plonk Interactive Oracle Proofs (PIOP) parameters.
#[derive(Clone)]
pub struct PiopParams<G: AffineRepr<BaseField: PrimeField>> {
    /// Domain over which the piop is represented.
    pub domain: Domain<G::BaseField>,
    /// Number of bits used to represent a scalar.
    pub scalar_bitlen: usize,
    /// Blinding base point.
    pub h: G,
}

impl<G: AffineRepr<BaseField: PrimeField>> PiopParams<G> {
    pub fn setup(domain: Domain<G::BaseField>, h: G) -> Self {
        let scalar_bitlen = G::ScalarField::MODULUS_BIT_SIZE as usize;
        Self {
            domain,
            scalar_bitlen,
            h,
        }
    }

    pub fn children_capacity(&self) -> usize {
        self.domain.capacity - 1
    }

    pub fn x_coords_column(&self, x_coords: Vec<G::BaseField>) -> FieldColumn<G::BaseField> {
        let c = self.children_capacity();
        assert!(x_coords.len() <= c);
        let mut x_coords = x_coords;
        x_coords.resize(self.domain.domain_size(), G::BaseField::zero());
        x_coords[c] = G::BaseField::one();
        self.domain.domains.column_from_evals(x_coords, c)
    }

    pub fn h_powers_column(&self) -> AffineColumn<G::BaseField, G> {
        let mut h_powers = self.power_of_2_multiples_of_h();
        h_powers.truncate(self.children_capacity());
        AffineColumn::public_column(h_powers, &self.domain)
    }

    pub fn node_selector(&self, node_index: usize) -> BitColumn<G::BaseField> {
        let c = self.children_capacity();
        let mut node_selector = vec![false; c];
        assert!(node_index < c); // allows to select a padding node
        node_selector[node_index] = true;
        BitColumn::init(node_selector, &self.domain)
    }

    pub fn bf_bits_column(&self, bf: G::ScalarField) -> BitColumn<G::BaseField> {
        let mut bf_bits = self.scalar_part(bf);
        bf_bits.truncate(self.children_capacity());
        BitColumn::init(bf_bits, &self.domain)
    }

    fn power_of_2_multiples_of_h(&self) -> Vec<G> {
        let mut h = self.h.into_group();
        let mut multiples = Vec::with_capacity(self.scalar_bitlen);
        multiples.push(h);
        for _ in 1..self.scalar_bitlen {
            h.double_in_place();
            multiples.push(h);
        }
        CurveGroup::normalize_batch(&multiples)
    }

    fn scalar_part(&self, e: G::ScalarField) -> Vec<bool> {
        let bits_with_trailing_zeroes = e.into_bigint().to_bits_le();
        let significant_bits = &bits_with_trailing_zeroes[..self.scalar_bitlen];
        significant_bits.to_vec()
    }
}

#[cfg(test)]
mod tests {}
