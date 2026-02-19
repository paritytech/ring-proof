use crate::domain::Domain;
use crate::gadgets::ec::AffineColumn;
use crate::gadgets::{ProverGadget, VerifierGadget};
use crate::{const_evals, Column, FieldColumn};
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Evaluations, GeneralEvaluationDomain};
use ark_std::ops::Mul;

use ark_std::{vec, vec::Vec};
use core::marker::PhantomData;

pub struct Doubling<F: FftField, P: AffineRepr<BaseField = F>> {
    pub doublings: AffineColumn<F, P>,
    // The polynomial `X - w^{n-1}` in the Lagrange basis
    not_last: FieldColumn<F>,
}

pub struct DoublingValues<F: Field, P: AffineRepr<BaseField = F>> {
    pub doublings: (F, F),
    pub not_last: F,
    pub _phantom: PhantomData<P>,
}

impl<F, P: AffineRepr<BaseField = F>> Doubling<F, P>
where
    F: FftField,
{
    pub fn init(p: P, domain: &Domain<F>) -> Self {
        let doublings = Self::doublings_of(p, domain.capacity);
        let doublings = AffineColumn::public_column(doublings, domain);
        let not_last = domain.not_last_row.clone();
        Self {
            doublings,
            not_last,
        }
    }

    pub fn doublings_of(p: P, n: usize) -> Vec<P> {
        let mut p = p.into_group();
        let mut doublings = Vec::with_capacity(n);
        doublings.push(p);
        for _ in 1..n {
            p.double_in_place();
            doublings.push(p);
        }
        CurveGroup::normalize_batch(&doublings)
    }

    fn evaluate_assignment(&self, z: &F) -> DoublingValues<F, P> {
        DoublingValues {
            doublings: self.doublings.evaluate(z),
            not_last: self.not_last.evaluate(z),
            _phantom: PhantomData,
        }
    }
}

impl<F: FftField, Curve> ProverGadget<F> for Doubling<F, Affine<Curve>>
where
    Curve: TECurveConfig<BaseField = F>,
{
    fn witness_columns(&self) -> Vec<DensePolynomial<F>> {
        vec![
            self.doublings.xs.poly.clone(),
            self.doublings.ys.poly.clone(),
        ]
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        let (x1, y1) = (&self.doublings.xs.evals_4x, &self.doublings.ys.evals_4x);
        let (x2, y2) = (
            &self.doublings.xs.shifted_4x(),
            &self.doublings.ys.shifted_4x(),
        );

        // a.x² + y² = 1 + d.x².y² -- twisted Edwards curve affine equation
        // 2(x1, y1) =: (x2, y2) -- doubling formula, where
        // x2 = 2.x1.y1 / (a.x1² + y1²) <=> x2.(a.x1² + y1²) - 2.x1.y1 = 0
        // y2 = (y1² - a.x1²) / (2 - a.x1² - y1²) <=> y2.(2 - a.x1² - y1²) + a.x1² - y1² = 0

        let x1_sq = &(x1 * x1);
        let y1_sq = &(y1 * y1);
        let x1y1 = &(x1 * y1);
        let a_x1_sq = &(x1_sq * Curve::COEFF_A);
        let two = &const_evals(F::from(2), self.not_last.domain_4x());

        // x2.(a.x1² + y1²) - 2.x1.y1 = 0
        let mut c1 = &(x2 * &(a_x1_sq + y1_sq)) - &(x1y1 * F::from(2));

        // y2.(2 - a.x1² - y1²) + a.x1² - y1² = 0
        let mut c2 = &(&(y2 * &(&(two - a_x1_sq) - y1_sq)) + a_x1_sq) - y1_sq;

        c1 *= &self.not_last.evals_4x;
        c2 *= &self.not_last.evals_4x;

        vec![c1, c2]
    }

    // TODO: rename, constraints_in_zeta_omega?
    fn constraints_linearized(&self, z: &F) -> Vec<DensePolynomial<F>> {
        let x2 = self.doublings.xs.as_poly();
        let y2 = self.doublings.ys.as_poly();
        let (x_coeff, y_coeff) = self.evaluate_assignment(z).get_coeffs();
        vec![x2 * x_coeff, y2 * y_coeff]
    }

    fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.not_last.domain()
    }
}

impl<F: FftField, Curve> VerifierGadget<F> for DoublingValues<F, Affine<Curve>>
where
    Curve: TECurveConfig<BaseField = F>,
{
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let (x1, y1) = self.doublings;
        let mut c1 = -(F::from(2) * x1 * y1);
        let mut c2 = Curve::COEFF_A * x1 * x1 - y1 * y1;
        c1 *= self.not_last;
        c2 *= self.not_last;
        vec![c1, c2]
    }
}

impl<F: FftField, Curve> DoublingValues<F, Affine<Curve>>
where
    Curve: TECurveConfig<BaseField = F>,
{
    pub fn get_coeffs(&self) -> (F, F) {
        let (x1, y1) = self.doublings;
        // x2.(a.x1² + y1²) - 2.x1.y1 = 0
        // y2.(2 - a.x1² - y1²) + a.x1² - y1² = 0
        let c = Curve::COEFF_A * x1 * x1 + y1 * y1; // a.x1² + y1²
        let mut x2_coeff = c;
        let mut y2_coeff = F::from(2) - c;
        x2_coeff *= self.not_last;
        y2_coeff *= self.not_last;
        (x2_coeff, y2_coeff)
    }
}

impl<F: PrimeField, Curve> DoublingValues<F, Affine<Curve>>
where
    Curve: TECurveConfig<BaseField = F>,
{
    pub fn zeta_omega_poly_commitment<C>(&self, cx: C, cy: C) -> Vec<C>
    where
        C: Mul<F, Output = C>,
    {
        let (x_coeff, y_coeff) = self.get_coeffs();
        vec![cx * x_coeff, cy * y_coeff]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq};
    use ark_poly::Polynomial;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn doubling_gadget() {
        let rng = &mut test_rng();

        let log_n = 4;
        let n = 2usize.pow(log_n);
        let domain = Domain::new(n, false);
        let p = EdwardsAffine::rand(rng);

        let gadget = Doubling::init(p, &domain);

        let c = gadget.constraints();
        let c = [c[0].interpolate_by_ref(), c[1].interpolate_by_ref()];
        assert_eq!(c[0].degree(), 3 * n - 2);
        assert_eq!(c[1].degree(), 3 * n - 2);

        // A valid witness satisfies the constraints.
        domain.divide_by_vanishing_poly(&c[0]);
        domain.divide_by_vanishing_poly(&c[1]);

        let z = Fq::rand(rng);
        let z_w = z * domain.omega();
        let evals_at_z = gadget.evaluate_assignment(&z);

        let c_z = evals_at_z.evaluate_constraints_main();
        let c_zw = gadget.constraints_linearized(&z);

        assert_eq!(c[0].evaluate(&z), c_z[0] + c_zw[0].evaluate(&z_w));
        assert_eq!(c[1].evaluate(&z), c_z[1] + c_zw[1].evaluate(&z_w));

        let x_col = gadget.doublings.xs.as_poly().clone();
        let y_col = gadget.doublings.ys.as_poly().clone();
        assert_eq!(
            gadget.constraints_linearized(&z),
            evals_at_z.zeta_omega_poly_commitment(x_col, y_col)
        );
    }
}
