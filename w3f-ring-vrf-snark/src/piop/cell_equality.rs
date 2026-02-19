use ark_ff::{FftField, Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::Evaluations;

use ark_std::{vec, vec::Vec};

use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::VerifierGadget;
use w3f_plonk_common::{Column, FieldColumn};

pub struct CellEqualityPolys<F: FftField> {
    a: FieldColumn<F>,
    b: FieldColumn<F>,
    l_last: FieldColumn<F>,
}

pub struct CellEqualityEvals<F: Field> {
    pub a: F,
    pub b: F,
    pub l_last: F,
}

impl<F: FftField> CellEqualityPolys<F> {
    pub fn init(a: FieldColumn<F>, b: FieldColumn<F>, domain: &Domain<F>) -> Self {
        assert_eq!(a.constrained_len(), domain.capacity);
        assert_eq!(b.constrained_len(), domain.capacity);
        let a_last = a.evals.evals[domain.capacity - 1];
        let b_last = b.evals.evals[domain.capacity - 1];
        assert_eq!(a_last, b_last);
        let l_last = domain.l_last.clone();
        Self { a, b, l_last }
    }

    pub fn constraints(&self) -> Vec<Evaluations<F>> {
        let a = &self.a.evals_4x;
        let b = &self.b.evals_4x;
        let l_last = &self.l_last.evals_4x;
        let c = l_last * &(a - b);
        vec![c]
    }

    pub fn constraints_linearized(&self, _z: &F) -> Vec<DensePolynomial<F>> {
        vec![DensePolynomial::zero()]
    }
}

impl<F: Field> VerifierGadget<F> for CellEqualityEvals<F> {
    fn evaluate_constraints_main(&self) -> Vec<F> {
        let c = self.l_last * (self.a - self.b);
        vec![c]
    }
}
