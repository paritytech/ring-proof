use ark_ff::{FftField, Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Evaluations, GeneralEvaluationDomain};

use ark_std::{vec, vec::Vec};

use crate::domain::Domain;
use crate::gadgets::{ProverGadget, VerifierGadget};
use crate::{const_evals, Column, FieldColumn};

pub struct FixedCells<F: FftField> {
    col: FieldColumn<F>,
    i: Vec<usize>,
    l_i: Vec<FieldColumn<F>>,
    col_i: Vec<F>,
}

pub struct FixedCellsValues<F: Field> {
    pub col: F,
    pub l_i: Vec<F>,
    pub col_i: Vec<F>,
}

impl<F: FftField> FixedCells<F> {
    pub fn init_unchecked(col: FieldColumn<F>, domain: &Domain<F>) -> Self {
        debug_assert_eq!(col.payload_len(), domain.capacity);
        let col_first = col.evals[0];
        let col_last = col.evals[domain.capacity - 1];
        Self::first_and_last(col, domain, col_first, col_last)
    }

    pub fn init(col: FieldColumn<F>, domain: &Domain<F>, col_first: F, col_last: F) -> Self {
        Self::first_and_last(col, domain, col_first, col_last)
    }

    pub fn first_and_last(
        col: FieldColumn<F>,
        domain: &Domain<F>,
        col_first: F,
        col_last: F,
    ) -> Self {
        debug_assert_eq!(col.payload_len(), domain.capacity);
        let l_first = domain.l_first.clone();
        let l_last = domain.l_last.clone();
        Self {
            col,
            i: vec![0, domain.capacity - 1],
            l_i: vec![l_first, l_last],
            col_i: vec![col_first, col_last],
        }
    }

    pub fn first(col: FieldColumn<F>, domain: &Domain<F>, col_first: F) -> Self {
        debug_assert_eq!(col.payload_len(), domain.capacity);
        let l_first = domain.l_first.clone();
        Self {
            col,
            i: vec![0],
            l_i: vec![l_first],
            col_i: vec![col_first],
        }
    }

    pub fn last(col: FieldColumn<F>, domain: &Domain<F>, col_last: F) -> Self {
        debug_assert_eq!(col.payload_len(), domain.capacity);
        let l_last = domain.l_last.clone();
        Self {
            col,
            i: vec![domain.capacity - 1],
            l_i: vec![l_last],
            col_i: vec![col_last],
        }
    }

    /// Constraints the column `col` to have the value `col[i]` at index `i`.
    /// `li` should be the `i-th` Lagrange basis polynomial `li = L_i(X)`.
    /// The constraint polynomial is `c(X) = L_i(X).col(X) - col[i].L_i(X)`.
    pub fn constraint_cell(
        col: &FieldColumn<F>,
        li: &FieldColumn<F>,
        i: usize,
        val: F,
    ) -> Evaluations<F> {
        assert_eq!(val, col.evals[i]);
        let domain = col.domain_4x();
        let val = &const_evals(val, domain);
        let col = &col.evals_4x;
        let li = &li.evals_4x;
        li * &(col - val)
    }
}

impl<F: FftField> ProverGadget<F> for FixedCells<F> {
    fn witness_columns(&self) -> Vec<DensePolynomial<F>> {
        todo!()
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        let c = self
            .i
            .iter()
            .zip(self.l_i.iter())
            .zip(self.col_i.iter())
            .map(|((i, l_i), col_i)| Self::constraint_cell(&self.col, l_i, *i, *col_i))
            .reduce(|acc, c| &acc + &c)
            .unwrap();
        // let c = &Self::constraint_cell(&self.col, &self.l_first, 0, self.col_first)
        //     + &Self::constraint_cell(&self.col, &self.l_last, domain_capacity - 1, self.col_last);
        vec![c]
    }

    fn constraints_linearized(&self, _z: &F) -> Vec<DensePolynomial<F>> {
        vec![DensePolynomial::zero()]
    }

    fn domain(&self) -> GeneralEvaluationDomain<F> {
        todo!()
    }
}

impl<F: Field> FixedCellsValues<F> {
    pub fn evaluate_for_cell(col_eval: F, li_eval: F, cell_val: F) -> F {
        li_eval * (col_eval - cell_val)
    }
}

impl<F: Field> VerifierGadget<F> for FixedCellsValues<F> {
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let c = self
            .l_i
            .iter()
            .zip(self.col_i.iter())
            .map(|(l_i, col_i)| Self::evaluate_for_cell(self.col, *l_i, *col_i))
            .sum();
        vec![c]
    }
}
