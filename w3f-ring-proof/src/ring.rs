use ark_ec::pairing::Pairing;
use ark_ec::twisted_edwards::{TECurveConfig};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt;
use ark_std::iter;
use ark_std::ops::Range;
use ark_std::vec::Vec;
use w3f_pcs::pcs::kzg::urs::URS;
use w3f_pcs::pcs::PcsParams;

use w3f_plonk_common::domain::ZK_ROWS;

use crate::PiopParams;

const IDLE_ROWS: usize = ZK_ROWS + 1;

/// Commitment to a list of VRF public keys as is used as a public input to the ring proof SNARK verifier.
///
/// The VRF keys are (inner) curve points that we represent in the affine Twisted Edwards coordinates.
/// We commit to the coordinate vectors independently using KZG on the outer curve. To make the commitment
/// updatable we use SRS in the Lagrangian form: `L1, ..., Ln`, where `Li = L_i(t)G`.
/// The commitment to a vector `a1, ..., an` is then `a1L1 + ... + anLn`.
///
/// We pad the list of keys with a `padding` point with unknown dlog up to a certain size.
/// Additionally, to make the commitment compatible with the snark,
/// we append the power-of-2 powers of the VRF blinding Pedersen base
/// `H, 2H, 4H, ..., 2^(s-1)H`, where `s` is the bitness of the VRF curve scalar field.
/// The last `IDLE_ROWS = 4` elements are set to `(0, 0)`.
///
/// Thus, the vector of points we commit to coordinatewise is
/// `pk1, ..., pkn, padding, ..., padding, H, 2H, ..., 2^(s-1)H, 0, 0, 0, 0`
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ring<
    F: PrimeField,
    KzgCurve: Pairing<ScalarField=F>,
    VrfCurve: AffineRepr<BaseField=F>,
> {
    /// KZG commitment to the x coordinates of the described vector.
    pub cx: KzgCurve::G1Affine,
    /// KZG commitment to the y coordinates of the described vector.
    pub cy: KzgCurve::G1Affine,
    /// KZG commitment to a bitvector highlighting the part of the vector corresponding to the public keys.
    pub selector: KzgCurve::G1Affine,
    /// Maximal number of keys the commitment can "store". For domain of size `N` it is `N - (s + IDLE_ROWS)`.
    pub max_keys: usize,
    /// Number of keys "stored" in this commitment.
    pub curr_keys: usize,
    // Padding point.
    pub padding: VrfCurve,
}

impl<
    F: PrimeField,
    KzgCurve: Pairing<ScalarField=F>,
    VrfCurve: AffineRepr<BaseField=F>,
> fmt::Debug for Ring<F, KzgCurve, VrfCurve>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ring(curr_keys={}, max_keys{})",
            self.curr_keys, self.max_keys
        )
    }
}

impl<
    F: PrimeField,
    KzgCurve: Pairing<ScalarField=F>,
    VrfCurve: AffineRepr<BaseField=F>,
> Ring<F, KzgCurve, VrfCurve>
where
    <VrfCurve as AffineRepr>::Config: TECurveConfig<BaseField=F>,
{
    /// Builds the commitment to the vector
    /// `padding, ..., padding, H, 2H, ..., 2^(s-1)H, 0, 0, 0, 0`.
    ///
    /// We compute it as a sum of commitments of 2 vectors:
    /// `padding, ..., padding`, and
    /// `0, ..., 0, (H - padding), (2H - padding), ..., (2^(s-1)H  - padding), -padding, -padding, -padding, -padding`.
    /// The first one is `padding * G`, the second requires an `(IDLE_ROWS + s)`-msm to compute.
    ///
    /// - `piop_params`: SNARK parameters
    /// - `srs`: Should return `srs[range]` for `range = (piop_params.keyset_part_size..domain_size)`
    /// - `g`: Generator used in the SRS
    pub fn empty(
        piop_params: &PiopParams<F, VrfCurve>,
        srs: impl Fn(Range<usize>) -> Result<Vec<KzgCurve::G1Affine>, ()>,
        g: KzgCurve::G1,
    ) -> Self {
        let (padding_x, padding_y) = piop_params.padding.xy().unwrap(); // panics on inf, never happens
        let c1x = g * padding_x;
        let c1y = g * padding_y;

        let powers_of_h = piop_params.power_of_2_multiples_of_h();
        let (mut xs, mut ys): (Vec<F>, Vec<F>) = powers_of_h
            .iter()
            .map(|p| p.xy().unwrap())
            .map(|(x, y)| (x - padding_x, y - padding_y))
            .unzip();
        xs.resize(xs.len() + IDLE_ROWS, -padding_x);
        ys.resize(ys.len() + IDLE_ROWS, -padding_y);
        let domain_size = piop_params.domain.domain().size();
        let srs_segment = &srs(piop_params.keyset_part_size..domain_size).unwrap();
        let c2x = KzgCurve::G1::msm(srs_segment, &xs).unwrap();
        let c2y = KzgCurve::G1::msm(srs_segment, &ys).unwrap();

        let selector_inv = srs_segment.iter().sum::<KzgCurve::G1>();
        let selector = g - selector_inv;

        let (cx, cy, selector) = {
            let affine = KzgCurve::G1::normalize_batch(&[c1x + c2x, c1y + c2y, selector]);
            (affine[0], affine[1], affine[2])
        };

        Self {
            cx,
            cy,
            selector,
            max_keys: piop_params.keyset_part_size,
            curr_keys: 0,
            padding: piop_params.padding,
        }
    }

    /// Appends a set key sequence to the ring.
    ///
    /// - `keys`: Keys to append.
    /// - `srs`: Should return `srs[range]` for `range = (self.curr_keys..self.curr_keys + keys.len())`
    pub fn append(
        &mut self,
        keys: &[VrfCurve],
        srs: impl Fn(Range<usize>) -> Result<Vec<KzgCurve::G1Affine>, ()>,
    ) {
        let new_size = self.curr_keys + keys.len();
        assert!(new_size <= self.max_keys);
        let (padding_x, padding_y) = self.padding.xy().unwrap();
        let (xs, ys): (Vec<F>, Vec<F>) = keys
            .iter()
            .map(|p| p.xy().unwrap())
            .map(|(x, y)| (x - padding_x, y - padding_y))
            .unzip();
        let srs_segment = &srs(self.curr_keys..self.curr_keys + keys.len()).unwrap();
        let cx_delta = KzgCurve::G1::msm(srs_segment, &xs).unwrap();
        let cy_delta = KzgCurve::G1::msm(srs_segment, &ys).unwrap();

        let (new_cx, new_cy) = {
            let affine = KzgCurve::G1::normalize_batch(&[self.cx + cx_delta, self.cy + cy_delta]);
            (affine[0], affine[1])
        };

        self.cx = new_cx;
        self.cy = new_cy;
        self.curr_keys = new_size;
    }

    /// Builds the ring from the keys provided with 2 MSMs of size `keys.len() + scalar_bitlen + 5`.
    ///
    /// In some cases it may be beneficial to cash the empty ring, as updating it costs 2 MSMs of size `keys.len()`.
    ///
    /// - `piop_params`: SNARK parameters.
    /// - `srs`: full-size Lagrangian SRS.
    pub fn with_keys(
        piop_params: &PiopParams<F, VrfCurve>,
        keys: &[VrfCurve],
        srs: &RingBuilderKey<F, KzgCurve>,
    ) -> Self {
        let (padding_x, padding_y) = piop_params.padding.xy().unwrap(); // panics on inf, never happens
        let powers_of_h = piop_params.power_of_2_multiples_of_h();

        // Computes
        // [(pk1 - padding), ..., (pkn - padding),
        //  (H - padding), ..., (2^(s-1)HH - padding),
        //  -padding, -padding, -padding, -padding,
        //  padding].
        let (xs, ys): (Vec<F>, Vec<F>) = keys
            .iter()
            .chain(&powers_of_h)
            .map(|p| p.xy().unwrap())
            .map(|(x, y)| (x - padding_x, y - padding_y))
            .chain(iter::repeat((-padding_x, -padding_y)).take(4))
            .chain(iter::once((padding_x, padding_y)))
            .unzip();

        // Composes the corresponding slices of the SRS.
        let bases = [
            &srs.lis_in_g1[..keys.len()],
            &srs.lis_in_g1[piop_params.keyset_part_size..],
            &[srs.g1.into()],
        ]
            .concat();

        let cx = KzgCurve::G1::msm(&bases, &xs).unwrap();
        let cy = KzgCurve::G1::msm(&bases, &ys).unwrap();
        let selector_inv = srs.lis_in_g1[piop_params.keyset_part_size..]
            .iter()
            .sum::<KzgCurve::G1>();
        let selector = srs.g1 - selector_inv;

        let (cx, cy, selector) = {
            let affine = KzgCurve::G1::normalize_batch(&[cx, cy, selector]);
            (affine[0], affine[1], affine[2])
        };

        Self {
            cx,
            cy,
            selector,
            max_keys: piop_params.keyset_part_size,
            curr_keys: keys.len(),
            padding: piop_params.padding,
        }
    }

    pub fn slots_left(&self) -> usize {
        self.max_keys - self.curr_keys
    }

    pub const fn empty_unchecked(
        domain_size: usize,
        cx: KzgCurve::G1Affine,
        cy: KzgCurve::G1Affine,
        selector: KzgCurve::G1Affine,
        padding: VrfCurve,
    ) -> Self {
        let max_keys =
            domain_size - (VrfCurve::ScalarField::MODULUS_BIT_SIZE as usize + IDLE_ROWS);
        Self {
            cx,
            cy,
            selector,
            max_keys,
            curr_keys: 0,
            padding,
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingBuilderKey<F: PrimeField, KzgCurve: Pairing<ScalarField=F>> {
    // Lagrangian SRS
    pub lis_in_g1: Vec<KzgCurve::G1Affine>,
    // generator used in the SRS
    pub g1: KzgCurve::G1,
}

impl<F: PrimeField, KzgCurve: Pairing<ScalarField=F>> RingBuilderKey<F, KzgCurve> {
    pub fn from_srs(srs: &URS<KzgCurve>, domain_size: usize) -> Self {
        let g1 = srs.powers_in_g1[0].into_group();
        let ck = srs.ck_with_lagrangian(domain_size);
        let lis_in_g1 = ck.lagrangian.unwrap().lis_in_g;
        Self { lis_in_g1, g1 }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine};
    use ark_std::{test_rng, UniformRand};
    use w3f_pcs::pcs::kzg::urs::URS;
    use w3f_pcs::pcs::kzg::KZG;
    use w3f_pcs::pcs::PCS;

    use w3f_plonk_common::domain::Domain;
    use w3f_plonk_common::test_helpers::random_vec;

    use crate::ring::Ring;
    use crate::PiopParams;

    use super::*;

    type TestRing = Ring<Fr, Bls12_381, BandersnatchConfig>;

    #[test]
    fn test_ring_mgmt() {
        let rng = &mut test_rng();

        let domain_size = 1 << 9;

        let pcs_params = KZG::<Bls12_381>::setup(domain_size - 1, rng);
        let ring_builder_key = RingBuilderKey::from_srs(&pcs_params, domain_size);
        let srs = |range: Range<usize>| Ok(ring_builder_key.lis_in_g1[range].to_vec());

        // piop params
        let h = EdwardsAffine::rand(rng);
        let seed = EdwardsAffine::rand(rng);
        let padding = EdwardsAffine::rand(rng);
        let domain = Domain::new(domain_size, true);
        let piop_params = PiopParams::setup(domain, h, seed, padding);

        let mut ring = TestRing::empty(&piop_params, srs, ring_builder_key.g1);
        let (monimial_cx, monimial_cy) = get_monomial_commitment(&pcs_params, &piop_params, &[]);
        assert_eq!(ring.cx, monimial_cx);
        assert_eq!(ring.cy, monimial_cy);

        let keys = random_vec::<EdwardsAffine, _>(ring.max_keys, rng);
        ring.append(&keys, srs);
        let (monimial_cx, monimial_cy) = get_monomial_commitment(&pcs_params, &piop_params, &keys);
        assert_eq!(ring.cx, monimial_cx);
        assert_eq!(ring.cy, monimial_cy);

        let same_ring = TestRing::with_keys(&piop_params, &keys, &ring_builder_key);
        assert_eq!(ring, same_ring);
    }

    #[test]
    fn test_empty_rings() {
        let rng = &mut test_rng();

        let domain_size = 1 << 9;

        let pcs_params = KZG::<Bls12_381>::setup(domain_size - 1, rng);
        let ring_builder_key = RingBuilderKey::from_srs(&pcs_params, domain_size);
        let srs = |range: Range<usize>| Ok(ring_builder_key.lis_in_g1[range].to_vec());

        // piop params
        let h = EdwardsAffine::rand(rng);
        let seed = EdwardsAffine::rand(rng);
        let padding = EdwardsAffine::rand(rng);
        let domain = Domain::new(domain_size, true);
        let piop_params = PiopParams::setup(domain, h, seed, padding);

        let ring = TestRing::empty(&piop_params, srs, ring_builder_key.g1);
        let same_ring = TestRing::with_keys(&piop_params, &[], &ring_builder_key);
        assert_eq!(ring, same_ring);
    }

    fn get_monomial_commitment(
        pcs_params: &URS<Bls12_381>,
        piop_params: &PiopParams<Fr, BandersnatchConfig>,
        keys: &[EdwardsAffine],
    ) -> (G1Affine, G1Affine) {
        let (_, verifier_key) =
            crate::piop::index::<_, KZG<Bls12_381>, _>(pcs_params, piop_params, keys);
        let [monimial_cx, monimial_cy] = verifier_key.fixed_columns_committed.points;
        (monimial_cx.0, monimial_cy.0)
    }
}
