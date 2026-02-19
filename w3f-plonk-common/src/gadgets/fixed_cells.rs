use ark_ff::{FftField, Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::Evaluations;

use ark_std::{vec, vec::Vec};

use crate::domain::Domain;
use crate::gadgets::VerifierGadget;
use crate::{const_evals, Column, FieldColumn};

pub struct FixedCells<F: FftField> {
    col: FieldColumn<F>,
    l_first: FieldColumn<F>,
    l_last: FieldColumn<F>,
}

pub struct FixedCellsValues<F: Field> {
    pub col: F,
    pub col_first: F,
    pub col_last: F,
    pub l_first: F,
    pub l_last: F,
}

impl<F: FftField> FixedCells<F> {
    pub fn init(col: FieldColumn<F>, domain: &Domain<F>) -> Self {
        assert_eq!(col.constrained_len, domain.capacity);
        let l_first = domain.l_first.clone();
        let l_last = domain.l_last.clone();
        Self {
            col,
            l_first,
            l_last,
        }
    }

    pub fn constraints(&self) -> Vec<Evaluations<F>> {
        let domain_capacity = self.col.constrained_len; // that's an ugly way to learn the capacity, but we've asserted it above.
        let c = &Self::constraint_cell(&self.col, &self.l_first, 0)
            + &Self::constraint_cell(&self.col, &self.l_last, domain_capacity - 1);
        vec![c]
    }

    pub fn constraints_linearized(&self, _z: &F) -> Vec<DensePolynomial<F>> {
        vec![DensePolynomial::zero()]
    }

    /// Constraints the column `col` to have the value `col[i]` at index `i`.
    /// `li` should be the `i-th` Lagrange basis polynomial `li = L_i(X)`.
    /// The constraint polynomial is `c(X) = L_i(X).col(X) - col[i].L_i(X)`.
    pub fn constraint_cell(col: &FieldColumn<F>, li: &FieldColumn<F>, i: usize) -> Evaluations<F> {
        let cell_val = col.evals[i];
        let domain = col.domain_4x();
        let cell_val = &const_evals(cell_val, domain);
        let col = &col.evals_4x;
        let li = &li.evals_4x;
        li * &(col - cell_val)
    }
}

impl<F: Field> FixedCellsValues<F> {
    pub fn evaluate_for_cell(col_eval: F, li_eval: F, cell_val: F) -> F {
        li_eval * (col_eval - cell_val)
    }
}

impl<F: Field> VerifierGadget<F> for FixedCellsValues<F> {
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let c = Self::evaluate_for_cell(self.col, self.l_first, self.col_first)
            + Self::evaluate_for_cell(self.col, self.l_last, self.col_last);
        vec![c]
    }
}
