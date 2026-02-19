use crate::domain::Domain;
use crate::gadgets::booleanity::BitColumn;
use crate::{Column, FieldColumn};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field};

// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;

pub mod sw_cond_add;
pub mod te_cond_add;
pub mod te_doubling;

// A vec of affine points from the prime-order subgroup of the curve whose base field enables FFTs,
// and its convenience representation as columns of coordinates over the curve's base field.

// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[derive(Clone)]
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
    pub result: P,
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
        assert_eq!(bitmask.bits.len(), domain.capacity - 1);
        // assert_eq!(points.points.len(), domain.capacity - 1); //TODO
        let not_last = domain.not_last_row.clone();
        let acc = bitmask
            .bits
            .iter()
            .zip(points.points.iter())
            .scan(seed, |acc, (&b, point)| {
                if b {
                    *acc = (*acc + point).into_affine();
                }
                Some(*acc)
            });
        let acc: Vec<_> = ark_std::iter::once(seed).chain(acc).collect();
        let init_plus_result = acc.last().unwrap();
        let result = init_plus_result.into_group() - seed.into_group();
        let result = result.into_affine();
        let acc = AffineColumn::private_column(acc, domain);

        Self {
            bitmask,
            points,
            acc,
            not_last,
            result,
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
}

pub struct CondAddValues<F: Field, P: AffineRepr<BaseField = F>> {
    pub bitmask: F,
    pub points: (F, F),
    pub not_last: F,
    pub acc: (F, F),
    pub _phantom: PhantomData<P>,
}

pub struct CondAddEvals<F: Field, P: AffineRepr<BaseField = F>> {
    pub bitmask_at_z: F,
    pub points_at_z: (F, F),
    pub not_last_at_z: F,
    pub acc_at_z: (F, F),
    pub acc_at_zw: (F, F),
    pub _phantom: PhantomData<P>,
}
