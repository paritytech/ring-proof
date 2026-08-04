use crate::cond_select::{bit_to_field, PointSelect};
use crate::domain::Domain;
use crate::gadgets::booleanity::BitColumn;
use crate::{Column, FieldColumn};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field};
use ark_poly::GeneralEvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;

pub mod sw_cond_add;
pub mod te_cond_add;
pub mod te_doubling;

// A vec of affine points from the prime-order subgroup of the curve whose base field enables FFTs,
// and its convenience representation as columns of coordinates over the curve's base field.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AffineColumn<F: FftField, P: AffineRepr<BaseField = F>> {
    points: Vec<P>,
    pub xs: FieldColumn<F>,
    pub ys: FieldColumn<F>,
}

impl<F: FftField, P: AffineRepr<BaseField = F>> AffineColumn<F, P> {
    fn _column(points: Vec<P>, domain: &Domain<F>, public: bool) -> Self {
        assert!(points.iter().all(|p| !p.is_zero()));
        let (xs, ys) = points.iter().map(|p| p.xy().unwrap()).unzip();
        let (xs, ys) = if public {
            (domain.public_column(xs), domain.public_column(ys))
        } else {
            (domain.column(xs), domain.column(ys))
        };
        Self { points, xs, ys }
    }
    pub fn column(points: Vec<P>, domain: &Domain<F>) -> Self {
        Self::_column(points, domain, false)
    }

    pub fn public_column(points: Vec<P>, domain: &Domain<F>) -> Self {
        Self::_column(points, domain, true)
    }

    pub fn evaluate(&self, z: &F) -> (F, F) {
        (self.xs.evaluate(z), self.ys.evaluate(z))
    }
}

impl<F: FftField, P: AffineRepr<BaseField = F>> Column<F, P> for AffineColumn<F, P> {
    fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.xs.domain()
    }

    fn domain_4x(&self) -> GeneralEvaluationDomain<F> {
        self.xs.domain_4x()
    }

    fn payload(&self) -> &[P] {
        &self.points
    }
}

// Conditional affine addition:
// if the bit is set for a point, add the point to the acc and store,
// otherwise copy the acc value
pub struct CondAdd<F: FftField, P: AffineRepr<BaseField = F>> {
    bitmask: BitColumn<F>,
    points: AffineColumn<F, P>,
    // The polynomial `X - w^{n-1}` in the Lagrange basis
    not_last: FieldColumn<F>,
    // Accumulates the (conditional) rolling sum of the points
    pub acc: AffineColumn<F, P>,
}

impl<F, P: AffineRepr<BaseField = F>> CondAdd<F, P>
where
    F: FftField,
{
    // Populates the `acc` column starting from the supplied `seed`.
    // Both SW and TE gadgets use non-complete formulas, so special cases have to be avoided.
    // If we assume the proofs of possession have been verified for the ring points,
    // this can be achieved by setting the seed to a point of unknown dlog from the prime order subgroup.
    // The bits are secret (the prover's ring position and blinding scalar), so the
    // accumulation adds unconditionally and selects the result arithmetically
    // rather than branching on them.
    pub fn init(
        bitmask: BitColumn<F>,
        points: AffineColumn<F, P>,
        seed: P,
        domain: &Domain<F>,
    ) -> Self
    where
        P::Group: PointSelect<F>,
    {
        debug_assert_eq!(bitmask.payload_len(), domain.capacity - 1);
        debug_assert_eq!(points.payload_len(), domain.capacity - 1);
        let not_last = domain.not_last_row.clone();
        let mut projective_acc = seed.into_group();
        let projective_points: Vec<_> = bitmask
            .bits
            .iter()
            .zip(points.points.iter())
            .map(|(&bit, point)| {
                let mut sum = projective_acc;
                sum += point;
                projective_acc = P::Group::select(bit_to_field(bit), &sum, &projective_acc);
                projective_acc
            })
            .collect();
        let mut acc = Vec::with_capacity(projective_points.len() + 1);
        acc.push(seed);
        acc.extend(P::Group::normalize_batch(&projective_points));
        let acc = AffineColumn::column(acc, domain);
        debug_assert_eq!(acc.payload_len(), domain.capacity);
        Self {
            bitmask,
            points,
            acc,
            not_last,
        }
    }

    fn evaluate_assignment(&self, z: &F) -> CondAddValues<F, P> {
        CondAddValues {
            bitmask: self.bitmask.evaluate(z),
            points: self.points.evaluate(z),
            not_last: self.not_last.evaluate(z),
            acc: self.acc.evaluate(z),
            _phantom: PhantomData,
        }
    }

    pub fn seed(&self) -> P {
        self.acc.payload()[0]
    }

    pub fn seed_plus_sum(&self) -> P {
        let len = self.acc.payload_len();
        self.acc.payload()[len - 1]
    }

    pub fn result(&self) -> P {
        let sum = self.seed_plus_sum() - self.seed();
        sum.into_affine()
    }
}

pub struct CondAddValues<F: Field, P: AffineRepr<BaseField = F>> {
    pub bitmask: F,
    pub points: (F, F),
    pub not_last: F,
    pub acc: (F, F),
    pub _phantom: PhantomData<P>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{random_bitvec, random_vec};
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, SWAffine};
    use ark_std::test_rng;

    // The acc column is committed, so its values are consensus-critical:
    // every row produced by the branch-free accumulation must equal the naive
    // conditional sum that the constraints encode and that proofs generated
    // before the hardening were built from.
    fn acc_matches_naive_accumulation<F, P>()
    where
        F: FftField,
        P: AffineRepr<BaseField = F>,
        P::Group: PointSelect<F>,
    {
        let rng = &mut test_rng();
        let domain = Domain::test_domain(256, true);
        let bits = random_bitvec(domain.capacity - 1, 0.5, rng);
        let points = random_vec::<P, _>(domain.capacity - 1, rng);
        let seed = P::generator();

        let gadget = CondAdd::init(
            BitColumn::init(bits.clone(), &domain),
            AffineColumn::column(points.clone(), &domain),
            seed,
            &domain,
        );

        let mut acc = seed.into_group();
        let expected: Vec<P> = bits
            .iter()
            .zip(&points)
            .map(|(&bit, point)| {
                if bit {
                    acc += point;
                }
                acc.into_affine()
            })
            .collect();

        assert_eq!(gadget.acc.payload()[0], seed);
        assert_eq!(&gadget.acc.payload()[1..], &expected[..]);
    }

    #[test]
    fn te_acc_matches_naive_accumulation() {
        acc_matches_naive_accumulation::<_, EdwardsAffine>();
    }

    #[test]
    fn sw_acc_matches_naive_accumulation() {
        acc_matches_naive_accumulation::<_, SWAffine>();
    }
}
