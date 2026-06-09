use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{Evaluations, GeneralEvaluationDomain};
use ark_std::vec::Vec;

pub mod booleanity;
// pub mod inner_prod_pub;
pub mod column_sum;
pub mod ec;
pub mod equal_cells;
pub mod fixed_cells;
pub mod inner_prod;
pub mod inner_prod_inv;

pub trait ProverGadget<F: FftField> {
    // Columns populated by the gadget.
    fn witness_columns(&self) -> Vec<DensePolynomial<F>>;

    // Constraint polynomials.
    fn constraints(&self) -> Vec<Evaluations<F>>;

    // 'Linearized' parts of the constraint polynomials.
    fn constraints_linearized(&self, zeta: &F) -> Vec<DensePolynomial<F>>;

    // Subgroup over which the columns are defined.
    fn domain(&self) -> GeneralEvaluationDomain<F>;
}

pub trait VerifierGadget<F: Field> {
    fn evaluate_constraints_main(&self) -> Vec<F>;
}
