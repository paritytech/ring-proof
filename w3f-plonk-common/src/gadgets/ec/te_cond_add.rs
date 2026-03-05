use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::ops::{AddAssign, MulAssign, SubAssign};
use ark_std::{vec, vec::Vec};

use crate::gadgets::ec::{CondAdd, CondAddEvals, CondAddValues};
use crate::gadgets::{ProverGadget, VerifierGadget};
use crate::{const_evals, Column};

/// These constraints are deduced from
/// "Affine addition formulae (independent of d) for twisted Edwards curves",
/// see e.g. formula (3) in https://eprint.iacr.org/2008/522.pdf.
/// Works for distinct prime-order points.
/// `cx = {[(a.x1.x2 + y1.y2).x3 - x1.y1 - x2.y2].b + (x3 - x1).(1 - b)}.not_last`
/// `cy = {[(x1.y2 - x2.y1).y3 - x1.y1 + x2.y2].b + (y3 - y1).(1 - b)}.not_last`
// Where:
/// `(x3, y3) = (x1, y1) + (x2, y2)`, if `b = 1`, and
/// `(x3, y3) = (x1, y1)` otherwise.
pub fn cond_te_addition<F>(
    te_coeff_a: F,
    b: &F,
    x1: &F,
    y1: &F,
    x2: &F,
    y2: &F,
    x3: F,
    y3: F,
    not_last: &F,
    one: F,
) -> Vec<F>
where
    F: Clone,
    F: for<'a> AddAssign<&'a F>,
    F: for<'a> SubAssign<&'a F>,
    F: for<'a> MulAssign<&'a F>,
{
    let mut x1y1 = x1.clone();
    x1y1 *= y1;
    let mut x2y2 = x2.clone();
    x2y2 *= y2;
    let mut y1y2 = y1.clone();
    y1y2 *= y2;
    let mut x2y1 = x2.clone();
    x2y1 *= y1;

    // lx = [(a.x1.x2 + y1.y2).x3 - x1.y1 - x2.y2].b
    let mut lx = te_coeff_a;
    lx *= x1;
    lx *= x2;
    lx += &y1y2;
    lx *= &x3;
    lx -= &x1y1;
    lx -= &x2y2;
    lx *= b;

    // ly = [(x1.y2 - x2.y1).y3 - x1.y1 + x2.y2].b
    let mut ly = x1.clone();
    ly *= y2;
    ly -= &x2y1;
    ly *= &y3;
    ly -= &x1y1;
    ly += &x2y2;
    ly *= b;

    // rx = (x3 - x1).(1 - b)
    // ry = (y3 - y1).(1 - b)
    let mut one_minus_b = one;
    one_minus_b -= b;
    let mut rx = x3;
    rx -= x1;
    rx *= &one_minus_b;
    let mut ry = y3;
    ry -= y1;
    ry *= &one_minus_b;

    // cx = {lx + rx}.not_last
    // cy = {ly + ry}.not_last
    lx += &rx;
    lx *= &not_last;
    ly += &ry;
    ly *= &not_last;

    vec![lx, ly]
}

impl<F, Curve> ProverGadget<F> for CondAdd<F, Affine<Curve>>
where
    F: FftField,
    Curve: TECurveConfig<BaseField = F>,
{
    fn witness_columns(&self) -> Vec<DensePolynomial<F>> {
        vec![self.acc.xs.poly.clone(), self.acc.ys.poly.clone()]
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        let domain = self.bitmask.domain_4x();
        let b = &self.bitmask.col.evals_4x;
        let one = const_evals(F::one(), domain);
        let te_coeff_a = const_evals(Curve::COEFF_A, domain);
        let not_last = &self.not_last.evals_4x;
        let (x1, y1) = (&self.acc.xs.evals_4x, &self.acc.ys.evals_4x);
        let (x2, y2) = (&self.points.xs.evals_4x, &self.points.ys.evals_4x);
        let (x3, y3) = (self.acc.xs.shifted_4x(), self.acc.ys.shifted_4x());
        cond_te_addition(te_coeff_a, b, x1, y1, x2, y2, x3, y3, not_last, one)
    }

    /// Mary-Oana Linearization technique. See: https://hackmd.io/0kdBl3GVSmmcB7QJe1NTuw?view#Linearization
    fn constraints_linearized(&self, z: &F) -> Vec<DensePolynomial<F>> {
        let vals = self.evaluate_assignment(z);
        let acc_x = self.acc.xs.as_poly();
        let acc_y = self.acc.ys.as_poly();

        let (c_acc_x, c_acc_y) = vals.acc_coeffs_1();
        let c1_lin = acc_x * c_acc_x + acc_y * c_acc_y; //though acc_y is 0

        let (c_acc_x, c_acc_y) = vals.acc_coeffs_2();
        let c2_lin = acc_x * c_acc_x + acc_y * c_acc_y; //though acc_x is 0

        vec![c1_lin, c2_lin]
    }

    fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.bitmask.domain()
    }
}

impl<F, Curve> CondAdd<F, Affine<Curve>>
where
    F: FftField,
    Curve: TECurveConfig<BaseField = F>,
{
    pub fn evaluate_at_z_and_zw(&self, zeta: &F) -> CondAddEvals<F, Affine<Curve>> {
        let zeta_omega = self.bitmask.domain().group_gen() * zeta;
        CondAddEvals {
            bitmask_at_z: self.bitmask.evaluate(zeta),
            points_at_z: self.points.evaluate(zeta),
            not_last_at_z: self.not_last.evaluate(zeta),
            acc_at_z: self.acc.evaluate(zeta),
            acc_at_zw: self.acc.evaluate(&zeta_omega),
            _phantom: Default::default(),
        }
    }
}

impl<F: Field, C: TECurveConfig<BaseField = F>> CondAddEvals<F, Affine<C>> {
    pub fn constraints_at_z(&self) -> Vec<F> {
        cond_te_addition(
            C::COEFF_A,
            &self.bitmask_at_z,
            &self.acc_at_z.0,
            &self.acc_at_z.1,
            &self.points_at_z.0,
            &self.points_at_z.1,
            self.acc_at_zw.0,
            self.acc_at_zw.1,
            &self.not_last_at_z,
            F::one(),
        )
    }
}

impl<F: Field, C: TECurveConfig<BaseField = F>> CondAddValues<F, Affine<C>> {
    pub fn acc_coeffs_1(&self) -> (F, F) {
        let b = self.bitmask;
        let (x1, y1) = self.acc;
        let (x2, y2) = self.points;

        let mut c_acc_x = b * (y1 * y2 + C::COEFF_A * x1 * x2) + F::one() - b;
        let mut c_acc_y = F::zero();

        c_acc_x *= self.not_last;
        c_acc_y *= self.not_last;

        (c_acc_x, c_acc_y)
    }

    pub fn acc_coeffs_2(&self) -> (F, F) {
        let b = self.bitmask;
        let (x1, y1) = self.acc;
        let (x2, y2) = self.points;

        let mut c_acc_x = F::zero();
        let mut c_acc_y = b * (x1 * y2 - x2 * y1) + F::one() - b;

        c_acc_x *= self.not_last;
        c_acc_y *= self.not_last;

        (c_acc_x, c_acc_y)
    }
}

impl<F: FftField, C: TECurveConfig<BaseField = F>> VerifierGadget<F>
    for CondAddValues<F, Affine<C>>
{
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let b = self.bitmask;
        let (x1, y1) = self.acc;
        let (x2, y2) = self.points;
        let (x3, y3) = (F::zero(), F::zero());

        //b (x_3 (y_1 y_2 + ax_1 x_2) - x_1 y_1 - y_2 x_2) + (1 - b) (x_3 - x_1) = 0
        let mut c1 = b * (x3 * (y1 * y2 + C::COEFF_A * x1 * x2) - (x1 * y1 + x2 * y2))
            + (F::one() - b) * (x3 - x1);

        //b (y_3 (x_1 y_2 - x_2 y_1) - x_1 y_1 + x_2 y_2) + (1 - b) (y_3 - y_1) = 0
        let mut c2 =
            b * (y3 * (x1 * y2 - x2 * y1) - (x1 * y1 - x2 * y2)) + (F::one() - b) * (y3 - y1);

        c1 *= self.not_last;
        c2 *= self.not_last;

        vec![c1, c2]
    }
}

#[cfg(test)]
mod tests {
    use crate::gadgets::ec::AffineColumn;
    use crate::gadgets::ec::BitColumn;
    use crate::gadgets::ec::Domain;
    use ark_ec::AffineRepr;
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq};
    use ark_poly::Polynomial;

    use ark_std::{test_rng, UniformRand};

    use crate::test_helpers::cond_sum;
    use crate::test_helpers::*;

    use super::*;

    fn _test_te_cond_add_gadget(hiding: bool) {
        let rng = &mut test_rng();

        let log_n = 10;
        let n = 2usize.pow(log_n);
        let domain = Domain::new(n, hiding);
        let seed = EdwardsAffine::generator();

        let bitmask = random_bitvec(domain.capacity - 1, 0.5, rng);
        let points = random_vec::<EdwardsAffine, _>(domain.capacity - 1, rng);
        let expected_res = seed + cond_sum(&bitmask, &points);

        let bitmask_col = BitColumn::init(bitmask, &domain);
        let points_col = AffineColumn::private_column(points, &domain);
        let gadget = CondAdd::init(bitmask_col, points_col, seed, &domain);
        let res = gadget.acc.points.last().unwrap();
        assert_eq!(res, &expected_res);

        let cs = gadget.constraints();
        let c1 = cs[0].interpolate_by_ref();
        let c2 = cs[1].interpolate_by_ref();
        assert_eq!(c1.degree(), 4 * n - 3);
        assert_eq!(c2.degree(), 4 * n - 3);

        let q1 = domain.divide_by_vanishing_poly(&c1);
        let q2 = domain.divide_by_vanishing_poly(&c2);

        let zeta = Fq::rand(rng);
        let domain_at_z = domain.evaluate(zeta);
        let evals = gadget.evaluate_at_z_and_zw(&zeta);
        let cs_at_z = evals.constraints_at_z();
        assert_eq!(
            domain_at_z.divide_by_vanishing_poly_in_zeta(cs_at_z[0]),
            q1.evaluate(&zeta)
        );
        assert_eq!(
            domain_at_z.divide_by_vanishing_poly_in_zeta(cs_at_z[1]),
            q2.evaluate(&zeta)
        );
    }

    #[test]
    fn test_te_cond_add_gadget() {
        _test_te_cond_add_gadget(false);
        _test_te_cond_add_gadget(true);
    }
}
