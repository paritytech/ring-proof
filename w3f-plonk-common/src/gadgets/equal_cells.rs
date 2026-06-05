use ark_ff::{FftField, Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::Evaluations;

use ark_std::{vec, vec::Vec};

use crate::domain::Domain;
use crate::gadgets::VerifierGadget;
use crate::{Column, FieldColumn};

pub struct CellsEqPolys<F: FftField> {
    a: FieldColumn<F>,
    b: FieldColumn<F>,
    li: FieldColumn<F>,
}

pub struct EqualCells<F: Field> {
    pub a: F,
    pub b: F,
    pub li: F,
}

impl<F: FftField> CellsEqPolys<F> {
    pub fn first_cells(a: FieldColumn<F>, b: FieldColumn<F>, domain: &Domain<F>) -> Self {
        Self::cells(a, b, 0, domain.l_first.clone(), domain)
    }

    pub fn last_cells(a: FieldColumn<F>, b: FieldColumn<F>, domain: &Domain<F>) -> Self {
        Self::cells(a, b, domain.capacity - 1, domain.l_last.clone(), domain)
    }

    pub fn cells(
        a: FieldColumn<F>,
        b: FieldColumn<F>,
        i: usize,
        li: FieldColumn<F>,
        domain: &Domain<F>,
    ) -> Self {
        assert_eq!(a.payload_len(), domain.capacity);
        assert_eq!(b.payload_len(), domain.capacity);
        assert_eq!(a.evals.evals[i], b.evals.evals[i]);
        Self { a, b, li }
    }

    pub fn constraints(&self) -> Vec<Evaluations<F>> {
        let a = &self.a.evals_4x;
        let b = &self.b.evals_4x;
        let li = &self.li.evals_4x;
        let c = li * &(a - b);
        vec![c]
    }

    pub fn constraints_linearized(&self, _z: &F) -> Vec<DensePolynomial<F>> {
        Self::constraints_lin()
    }

    pub fn first_constraints(
        a: FieldColumn<F>,
        b: FieldColumn<F>,
        domain: &Domain<F>,
    ) -> Vec<Evaluations<F>> {
        let gadget = Self::first_cells(a, b, domain);
        gadget.constraints()
    }

    pub fn last_constraints(
        a: FieldColumn<F>,
        b: FieldColumn<F>,
        domain: &Domain<F>,
    ) -> Vec<Evaluations<F>> {
        let gadget = Self::last_cells(a, b, domain);
        gadget.constraints()
    }

    pub fn constraints_lin() -> Vec<DensePolynomial<F>> {
        vec![DensePolynomial::zero()]
    }
}

impl<F: Field> VerifierGadget<F> for EqualCells<F> {
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let c = self.li * (self.a - self.b);
        vec![c]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::random_vec;
    use ark_ed_on_bls12_381_bandersnatch::Fq;
    use ark_poly::Polynomial;
    use ark_std::test_rng;

    fn _test_equal_cells_gadget(zk_rows: usize) {
        let rng = &mut test_rng();

        let log_n = 8;
        let n = 1 << log_n;
        let domain = Domain::with_zk_rows(n, zk_rows);

        let a = random_vec(domain.capacity, rng);
        let mut b = random_vec(domain.capacity, rng);
        b[0] = a[0];
        let a = domain.column(a);
        let b = domain.column(b);

        let constraints_first = CellsEqPolys::<Fq>::first_constraints(a, b, &domain);
        let constraint_poly = constraints_first[0].interpolate_by_ref();
        assert_eq!(constraint_poly.degree(), 2 * n - 2);
        assert!(domain.compute_quotient(&constraint_poly).is_some());

        let a = random_vec(domain.capacity, rng);
        let mut b = random_vec(domain.capacity, rng);
        b[domain.capacity - 1] = a[domain.capacity - 1];
        let a = domain.column(a);
        let b = domain.column(b);

        let constraints_last = CellsEqPolys::<Fq>::last_constraints(a, b, &domain);
        let constraint_poly = constraints_last[0].interpolate_by_ref();
        assert_eq!(constraint_poly.degree(), 2 * n - 2);
        assert!(domain.compute_quotient(&constraint_poly).is_some());
    }

    #[test]
    fn test_equal_cells_gadget() {
        _test_equal_cells_gadget(0);
        _test_equal_cells_gadget(3);
    }
}
