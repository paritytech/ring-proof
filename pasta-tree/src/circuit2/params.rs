use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
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
    pub select_size: usize,
    /// Number of bits used to represent a scalar.
    pub rerand_size: usize,
    pub seed: G,
    /// Blinding base point.
    pub h: G,
}

impl<G: SWCurveConfig<BaseField: PrimeField>> PiopParams<SwAffine<G>> {
    pub fn setup(domain: Domain<G::BaseField>, h: SwAffine<G>, seed: SwAffine<G>) -> Self {
        assert!(domain.domain_size() > 256);
        let actual_capacity = domain.capacity - 1;
        let scalar_size = Domain::<G::BaseField>::new(256, domain.is_hiding()).capacity - 1;
        let rerand_size = ark_std::cmp::min(G::ScalarField::MODULUS_BIT_SIZE as usize, scalar_size);
        let select_size = actual_capacity - rerand_size;
        Self {
            domain,
            select_size,
            rerand_size,
            seed,
            h,
        }
    }

    pub fn max_nodes(&self) -> usize {
        self.select_size
    }

    pub fn points_column(
        &self,
        nodes: Vec<SwAffine<G>>,
    ) -> AffineColumn<G::BaseField, SwAffine<G>> {
        assert!(nodes.len() <= self.select_size);
        let mut points = nodes;
        let zero = SwAffine::<G>::new_unchecked(G::BaseField::ZERO, G::BaseField::ZERO);
        points.resize(self.select_size, zero);
        let powers_of_h = self.power_of_h();
        assert_eq!(powers_of_h.len(), self.rerand_size);
        points.extend(powers_of_h);
        // let flag = SwAffine::<G>::new_unchecked(G::BaseField::ONE, G::BaseField::ZERO);
        // points.push(flag);
        AffineColumn::public_column(points, &self.domain)
    }

    pub fn bits_column(&self, node_index: usize, bf: G::ScalarField) -> BitColumn<G::BaseField> {
        let mut bits = vec![false; self.select_size];
        assert!(node_index < self.select_size); // allows to select a padding node
        bits[node_index] = true;
        bits.extend(self.scalar_part(bf));
        BitColumn::init(bits, &self.domain)
    }

    pub fn select_part(&self) -> FieldColumn<G::BaseField> {
        let selector = [
            vec![G::BaseField::one(); self.select_size],
            vec![G::BaseField::zero(); self.rerand_size],
        ]
        .concat();
        self.domain.public_column(selector)
    }

    fn power_of_h(&self) -> Vec<SwAffine<G>> {
        let mut h = self.h.into_group();
        let mut res = Vec::with_capacity(self.rerand_size);
        res.push(h);
        for _ in 1..self.rerand_size {
            h.double_in_place();
            res.push(h);
        }
        CurveGroup::normalize_batch(&res)
    }

    fn scalar_part(&self, e: G::ScalarField) -> Vec<bool> {
        let bits_with_trailing_zeroes = e.into_bigint().to_bits_le();
        let significant_bits = &bits_with_trailing_zeroes[..self.rerand_size];
        significant_bits.to_vec()
    }
}

#[cfg(test)]
mod tests {}
