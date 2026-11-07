use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Evaluations, GeneralEvaluationDomain};

use ark_std::{vec, vec::Vec};

use crate::cond_select::CondSelect;
use crate::domain::Domain;
use crate::gadgets::booleanity::BitColumn;
use crate::gadgets::{ProverGadget, VerifierGadget};
use crate::{Column, FieldColumn};

pub struct InnerProd<F: FftField> {
    a: FieldColumn<F>,
    b: FieldColumn<F>,
    not_last: FieldColumn<F>,
    pub acc: FieldColumn<F>,
}

pub struct InnerProdValues<F: Field> {
    pub a: F,
    pub b: F,
    pub not_last: F,
    pub acc: F,
}

impl<F: FftField> InnerProd<F> {
    pub fn init(a: FieldColumn<F>, b: FieldColumn<F>, domain: &Domain<F>) -> Self {
        // we need an extra slot to seed the partial inner products acc with `0`.
        assert_eq!(a.payload_len(), domain.capacity - 1);
        assert_eq!(b.payload_len(), domain.capacity - 1);
        let inner_prods = Self::partial_inner_prods(a.payload(), b.payload());
        let mut acc = vec![F::zero()];
        acc.extend(inner_prods);
        let acc = domain.column(acc);
        Self {
            a,
            b,
            not_last: domain.not_last_row.clone(),
            acc,
        }
    }

    /// Same as `init` with `b` the field representation of `bits`, but the
    /// products are computed with a constant-time select, so the
    /// accumulation does not branch on the bits.
    pub fn init_bits(a: FieldColumn<F>, bits: &BitColumn<F>, domain: &Domain<F>) -> Self
    where
        F: CondSelect,
    {
        assert_eq!(a.payload_len(), domain.capacity - 1);
        assert_eq!(bits.payload_len(), domain.capacity - 1);
        let inner_prods = Self::partial_bit_prods(a.payload(), &bits.bits);
        let mut acc = vec![F::zero()];
        acc.extend(inner_prods);
        let acc = domain.column(acc);
        Self {
            a,
            b: bits.col.clone(),
            not_last: domain.not_last_row.clone(),
            acc,
        }
    }

    /// Returns a[0]b[0], a[0]b[0] + a[1]b[1], ..., a[0]b[0] + a[1]b[1] + ... + a[n-1]b[n-1]
    fn partial_inner_prods(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b)
            .scan(F::zero(), |state, (&a, b)| {
                *state += a * b;
                Some(*state)
            })
            .collect()
    }

    fn partial_bit_prods(a: &[F], bits: &[bool]) -> Vec<F>
    where
        F: CondSelect,
    {
        assert_eq!(a.len(), bits.len());
        a.iter()
            .zip(bits)
            .scan(F::zero(), |state, (&a, &bit)| {
                let sum = *state + a;
                *state = F::select(bit, &sum, state);
                Some(*state)
            })
            .collect()
    }
}

impl<F: FftField> ProverGadget<F> for InnerProd<F> {
    fn witness_columns(&self) -> Vec<DensePolynomial<F>> {
        vec![self.acc.poly.clone()]
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        let a = &self.a.evals_4x;
        let b = &self.b.evals_4x;
        let acc = &self.acc.evals_4x;
        let acc_shifted = &self.acc.shifted_4x();
        let not_last = &self.not_last.evals_4x;
        let c = &(&(acc_shifted - acc) - &(a * b)) * not_last;
        vec![c]
    }

    fn constraints_linearized(&self, z: &F) -> Vec<(DensePolynomial<F>, F)> {
        let nl = self.not_last.evaluate(z);
        let c = &self.acc.poly * nl;
        vec![(c, self.acc.bf * nl)]
    }

    fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.a.evals.domain()
    }
}

impl<F: Field> VerifierGadget<F> for InnerProdValues<F> {
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let c = (-self.acc - self.a * self.b) * self.not_last;
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
    use crate::test_helpers::{random_bitvec, random_vec};

    use super::*;

    fn inner_prod<F: Field>(a: &[F], b: &[F]) -> F {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b).map(|(a, b)| *a * b).sum()
    }

    fn _test_inner_prod_gadget(hiding: bool) {
        let rng = &mut test_rng();

        let log_n = 10;
        let n = 2usize.pow(log_n);
        let domain = Domain::test_domain(n, hiding);

        let a = random_vec(domain.capacity - 1, rng);
        let b = random_vec(domain.capacity - 1, rng);
        let ab = inner_prod(&a, &b);
        let a = domain.column(a);
        let b = domain.column(b);

        let gadget = InnerProd::<Fq>::init(a, b, &domain);

        let acc = &gadget.acc.evals.evals;
        assert!(acc[0].is_zero());
        assert_eq!(acc[domain.capacity - 1], ab);

        let constraint_poly = gadget.constraints()[0].interpolate_by_ref();

        assert_eq!(constraint_poly.degree(), 2 * n - 1);
        assert!(domain.compute_quotient(&constraint_poly).is_some());
    }

    #[test]
    fn test_inner_prod_gadget() {
        _test_inner_prod_gadget(false);
        _test_inner_prod_gadget(true);
    }

    // The acc column is committed, so its values are consensus-critical:
    // the branch-free bit accumulation must produce exactly the column the
    // naive product accumulation produces. Only the payload rows are
    // compared: the trailing zk rows are random per column instance.
    #[test]
    fn bit_acc_matches_naive_accumulation() {
        let rng = &mut test_rng();
        let domain = Domain::test_domain(256, true);
        let a: Vec<Fq> = random_vec(domain.capacity - 1, rng);
        let bits = random_bitvec(domain.capacity - 1, 0.5, rng);

        let naive = InnerProd::init(
            domain.column(a.clone()),
            domain.column(bits.iter().map(|&bit| Fq::from(bit)).collect()),
            &domain,
        );
        let bit_col = BitColumn::init(bits, &domain);
        let gadget = InnerProd::init_bits(domain.column(a), &bit_col, &domain);

        assert_eq!(
            gadget.acc.evals.evals[..domain.capacity],
            naive.acc.evals.evals[..domain.capacity]
        );
    }
}
