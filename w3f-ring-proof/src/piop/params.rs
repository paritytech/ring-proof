use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{vec, vec::Vec};

use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::ec::AffineColumn;

use crate::piop::FixedColumns;

/// Plonk Interactive Oracle Proofs (PIOP) parameters.
#[derive(Clone)]
pub struct PiopParams<F: PrimeField, Curve: SWCurveConfig<BaseField = F>> {
    /// Domain over which the piop is represented.
    pub domain: Domain<F>,
    /// Number of bits used to represent a jubjub scalar.
    pub(crate) scalar_bitlen: usize,
    /// Length of the part of the column representing the public keys (including the padding).
    pub keyset_part_size: usize,
    /// Blinding base point.
    pub h: Affine<Curve>, //TODO: make a method
    /// Summation base point.
    pub(crate) seed: Affine<Curve>,
    /// The point used to pad the list of public keys.
    pub(crate) padding: Affine<Curve>,
}

impl<F: PrimeField, Curve: SWCurveConfig<BaseField = F>> PiopParams<F, Curve> {
    /// Initialize PIOP parameters.
    ///
    /// - `domain`: polynomials evaluation domain.
    /// - `h`: Blinding base point.
    /// - `seed`: Accumulation base point
    /// - `padding`: The point used to pad the list of public keys.
    ///
    /// All points should be of an unknown discrete log.
    pub fn setup(
        domain: Domain<F>,
        h: Affine<Curve>,
        seed: Affine<Curve>,
        padding: Affine<Curve>,
    ) -> Self {
        let scalar_bitlen = Curve::ScalarField::MODULUS_BIT_SIZE as usize;
        // 1 accounts for the last cells of the points and bits columns that remain unconstrained
        let keyset_part_size = domain.capacity - scalar_bitlen - 1;
        Self {
            domain,
            scalar_bitlen,
            keyset_part_size,
            h,
            seed,
            padding,
        }
    }

    pub fn fixed_columns(&self, keys: &[Affine<Curve>]) -> FixedColumns<F, Affine<Curve>> {
        let ring_selector = self.keyset_part_selector();
        let ring_selector = self.domain.public_column(ring_selector);
        let points = self.points_column(&keys);
        FixedColumns {
            points,
            ring_selector,
        }
    }

    pub fn points_column(&self, keys: &[Affine<Curve>]) -> AffineColumn<F, Affine<Curve>> {
        assert!(keys.len() <= self.keyset_part_size);
        let padding_len = self.keyset_part_size - keys.len();
        let padding = vec![self.padding; padding_len];
        let points = [keys, &padding, &self.power_of_2_multiples_of_h()].concat();
        assert_eq!(points.len(), self.domain.capacity - 1);
        AffineColumn::public_column(points, &self.domain)
    }

    pub fn power_of_2_multiples_of_h(&self) -> Vec<Affine<Curve>> {
        let mut h = self.h.into_group();
        let mut multiples = Vec::with_capacity(self.scalar_bitlen);
        multiples.push(h);
        for _ in 1..self.scalar_bitlen {
            h.double_in_place();
            multiples.push(h);
        }
        CurveGroup::normalize_batch(&multiples)
    }

    pub fn scalar_part(&self, e: Curve::ScalarField) -> Vec<bool> {
        let bits_with_trailing_zeroes = e.into_bigint().to_bits_le();
        let significant_bits = &bits_with_trailing_zeroes[..self.scalar_bitlen];
        significant_bits.to_vec()
    }

    pub fn keyset_part_selector(&self) -> Vec<F> {
        [
            vec![F::one(); self.keyset_part_size],
            vec![F::zero(); self.scalar_bitlen],
        ]
        .concat()
    }

    pub fn blind_pk(&self, pk_k: Affine<Curve>, blinding: Curve::ScalarField) -> Affine<Curve> {
        let blinded_pk = pk_k + self.h * blinding;
        blinded_pk.into_affine()
    }
}

#[cfg(test)]
mod tests {
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, Fq, Fr, SWAffine};
    use ark_std::ops::Mul;
    use ark_std::{test_rng, UniformRand};

    use w3f_plonk_common::domain::Domain;
    use w3f_plonk_common::test_helpers::cond_sum;

    use crate::piop::params::PiopParams;

    #[test]
    fn test_powers_of_h() {
        let rng = &mut test_rng();
        let h = SWAffine::rand(rng);
        let seed = SWAffine::rand(rng);
        let padding = SWAffine::rand(rng);
        let domain = Domain::new(1024, false);

        let params = PiopParams::<Fq, BandersnatchConfig>::setup(domain, h, seed, padding);
        let t = Fr::rand(rng);
        let t_bits = params.scalar_part(t);
        let th = cond_sum(&t_bits, &params.power_of_2_multiples_of_h());
        assert_eq!(th, params.h.mul(t));
    }
}
