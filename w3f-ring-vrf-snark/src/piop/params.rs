use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{vec, vec::Vec};

use crate::piop::FixedColumns;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::booleanity::BitColumn;
use w3f_plonk_common::gadgets::ec::te_doubling::Doubling;
use w3f_plonk_common::gadgets::ec::AffineColumn;

#[derive(Clone)]
pub struct PiopParams<F: PrimeField, Curve: TECurveConfig<BaseField = F>> {
    /// The domain over which the piop is represented.
    pub(crate) domain: Domain<F>,
    /// The number of bits required to represent a jubjub scalar (a secret key).
    pub(crate) scalar_bitlen: usize,
    /// The generator used to compute public keys, `pk = sk.G`.
    pub(crate) g: Affine<Curve>,
    /// The point from which EC summations start.
    /// For curves in TE form, should be an odd-order point of an unknown dlog.
    /// Then we require:
    /// 1. *the proofs of possession are checked for every public key in the ring*,
    /// 2. the `padding` is chosen independently of the `seed`,
    /// 3. the inputs `vrf_in` are independent of the `seed`
    /// to avoid the doublings.
    pub(crate) seed: Affine<Curve>,
    /// The point used to pad the list of public keys up to the `domain.capacity - 1`.
    /// Should be of an unknown dlog.
    pub(crate) padding: Affine<Curve>,
}

impl<F: PrimeField, Curve: TECurveConfig<BaseField = F>> PiopParams<F, Curve> {
    pub fn setup(domain: Domain<F>, seed: Affine<Curve>, padding: Affine<Curve>) -> Self {
        let scalar_bitlen = Curve::ScalarField::MODULUS_BIT_SIZE as usize;
        assert!(scalar_bitlen + 1 <= domain.capacity); // 1 accounts for the seed cells
        Self {
            domain,
            scalar_bitlen,
            g: Affine::<Curve>::generator(),
            seed,
            padding,
        }
    }

    pub fn max_keys(&self) -> usize {
        self.domain.capacity - 1
    }

    pub fn fixed_columns(&self, pks: Vec<Affine<Curve>>) -> FixedColumns<F, Affine<Curve>> {
        // TODO: doublings_of_g.len() != pks.len()
        FixedColumns {
            pks: self.pks_col(pks),
            doublings_of_g: self.doublings_of_g_col(),
        }
    }

    fn pks_col(&self, pks: Vec<Affine<Curve>>) -> AffineColumn<F, Affine<Curve>> {
        assert!(pks.len() <= self.max_keys());
        let mut pks = pks;
        pks.resize(self.max_keys(), self.padding);
        let pks = AffineColumn::public_column(pks, &self.domain);
        pks
    }

    fn doublings_of_g_col(&self) -> AffineColumn<F, Affine<Curve>> {
        let doublings_of_g = Doubling::doublings_of(self.g, &self.domain.capacity - 1);
        AffineColumn::public_column(doublings_of_g, &self.domain)
    }

    /// Represents `index` as a binary column.
    pub fn pk_index_col(&self, index: usize) -> BitColumn<F> {
        assert!(index < self.max_keys());
        let mut col = vec![false; self.max_keys()];
        col[index] = true;
        BitColumn::init(col, &self.domain)
    }

    /// Represents a scalar in binary.
    pub fn sk_bits(&self, sk: Curve::ScalarField) -> Vec<bool> {
        let bits_with_trailing_zeroes = sk.into_bigint().to_bits_le();
        let significant_bits = &bits_with_trailing_zeroes[..self.scalar_bitlen];
        significant_bits.to_vec()
    }
}
