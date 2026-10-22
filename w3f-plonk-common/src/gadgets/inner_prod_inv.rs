use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Evaluations, GeneralEvaluationDomain};

use ark_std::{vec, vec::Vec};

use crate::domain::Domain;
use crate::gadgets::{ProverGadget, VerifierGadget};
use crate::{Column, FieldColumn};

/// Does the same as `inner_prod.rs`, but with the witness column reversed.
/// The input vectors keep the normal ordering. The witness column contains
/// the seed at `acc[domain.capacity - 1] = seed`
/// and the inner product result at `acc[0] = seed + <a,b>`.
pub struct InnerProdInv<F: FftField> {
    a: FieldColumn<F>,
    b: FieldColumn<F>,
    not_last: FieldColumn<F>,
    pub acc: FieldColumn<F>,
}

pub struct InnerProdInvValues<F: Field> {
    pub a: F,
    pub b: F,
    pub not_last: F,
    pub acc: F,
}

impl<F: FftField> InnerProdInv<F> {
    pub fn init(a: FieldColumn<F>, b: FieldColumn<F>, domain: &Domain<F>) -> Self {
        // we need an extra slot to seed the partial inner products acc with `0`.
        assert_eq!(a.payload_len(), domain.capacity - 1);
        assert_eq!(b.payload_len(), domain.capacity - 1);
        let inner_prods = Self::partial_inner_prods(a.payload(), b.payload());
        let mut acc = vec![F::zero()];
        acc.extend(inner_prods);
        acc.reverse();
        let acc = domain.column(acc);
        Self {
            a,
            b,
            not_last: domain.not_last_row.clone(),
            acc,
        }
    }

    /// Returns a[n-1]b[n-1], a[n-1]b[n-1] + a[n-2]b[n-2], ..., a[0]b[0] + a[1]b[1] + ... + a[n-1]b[n-1]
    fn partial_inner_prods(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len());
        a.iter()
            .rev()
            .zip(b.iter().rev())
            .scan(F::zero(), |state, (&a, b)| {
                *state += a * b;
                Some(*state)
            })
            .collect()
    }
}

impl<F: FftField> ProverGadget<F> for InnerProdInv<F> {
    fn witness_columns(&self) -> Vec<DensePolynomial<F>> {
        vec![self.acc.poly.clone()]
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        let a = &self.a.evals_4x;
        let b = &self.b.evals_4x;
        let acc = &self.acc.evals_4x;
        let acc_shifted = &self.acc.shifted_4x();
        let not_last = &self.not_last.evals_4x;
        let c = &(&(acc - acc_shifted) - &(a * b)) * not_last;
        vec![c]
    }

    fn constraints_linearized(&self, _z: &F) -> Vec<DensePolynomial<F>> {
        let c = -(&self.acc.poly * self.not_last.evaluate(_z));
        vec![c]
    }

    fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.a.evals.domain()
    }
}

impl<F: Field> VerifierGadget<F> for InnerProdInvValues<F> {
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let c = (self.acc - self.a * self.b) * self.not_last;
        vec![c]
    }
}

#[cfg(test)]
mod tests {
    use ark_ed_on_bls12_381_bandersnatch::Fq;
    use ark_ff::{Field, Zero};
    use ark_poly::Polynomial;
    use ark_std::test_rng;

    use crate::domain::Domain;
    use crate::test_helpers::random_vec;

    use super::*;

    fn inner_prod<F: Field>(a: &[F], b: &[F]) -> F {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b).map(|(a, b)| *a * b).sum()
    }

    fn _test_inner_prod_inv_gadget(zk_rows: usize) {
        let rng = &mut test_rng();

        let log_n = 10;
        let n = 2usize.pow(log_n);
        let domain = Domain::with_zk_rows(n, zk_rows);

        let a = random_vec(domain.capacity - 1, rng);
        let b = random_vec(domain.capacity - 1, rng);
        let ab = inner_prod(&a, &b);
        let a = domain.column(a);
        let b = domain.column(b);

        let gadget = InnerProdInv::<Fq>::init(a, b, &domain);

        let acc = &gadget.acc.evals.evals;
        assert!(acc[domain.capacity - 1].is_zero());
        assert_eq!(acc[0], ab);

        let constraint_poly = gadget.constraints()[0].interpolate_by_ref();

        assert_eq!(constraint_poly.degree(), 2 * n - 1);
        assert!(domain.compute_quotient(&constraint_poly).is_some());
    }

    #[test]
    fn test_inner_prod_inv_gadget() {
        _test_inner_prod_inv_gadget(0);
        _test_inner_prod_inv_gadget(3);
    }
}
