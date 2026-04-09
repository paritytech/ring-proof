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
    fn column(points: Vec<P>, domain: &Domain<F>, hidden: bool) -> Self {
        assert!(points.iter().all(|p| !p.is_zero()));
        let (xs, ys) = points.iter().map(|p| p.xy().unwrap()).unzip();
        let xs = domain.column(xs, hidden);
        let ys = domain.column(ys, hidden);
        Self { points, xs, ys }
    }
    pub fn private_column(points: Vec<P>, domain: &Domain<F>) -> Self {
        Self::column(points, domain, true)
    }

    pub fn public_column(points: Vec<P>, domain: &Domain<F>) -> Self {
        Self::column(points, domain, false)
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
    pub fn init(
        bitmask: BitColumn<F>,
        points: AffineColumn<F, P>,
        seed: P,
        domain: &Domain<F>,
    ) -> Self {
        debug_assert_eq!(bitmask.payload_len(), domain.capacity - 1);
        debug_assert_eq!(points.payload_len(), domain.capacity - 1);
        let not_last = domain.not_last_row.clone();
        let mut projective_acc = seed.into_group();
        let projective_points: Vec<_> = bitmask
            .bits
            .iter()
            .zip(points.points.iter())
            .map(|(&b, point)| {
                if b {
                    projective_acc += point;
                }
                projective_acc
            })
            .collect();
        let mut acc = Vec::with_capacity(projective_points.len() + 1);
        acc.push(seed);
        acc.extend(P::Group::normalize_batch(&projective_points));
        let acc = AffineColumn::private_column(acc, domain);
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
