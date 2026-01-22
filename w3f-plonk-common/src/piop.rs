use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Evaluations;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use w3f_pcs::pcs::Commitment;

use crate::domain::{Domain, EvaluatedDomain};
use crate::{ColumnsCommited, ColumnsEvaluated};

pub trait ProverPiop<F: PrimeField, C: Commitment<F>> {
    type Commitments: ColumnsCommited<F, C>;
    type Evaluations: ColumnsEvaluated<F>;
    type Instance: CanonicalSerialize + CanonicalDeserialize;

    // Commitments to the column polynomials excluding the precommitted columns.
    fn committed_columns<Fun: Fn(&DensePolynomial<F>) -> C>(
        &self,
        commit: Fun,
    ) -> Self::Commitments;

    // All the column polynomials (including precommitted columns)
    fn columns(&self) -> Vec<DensePolynomial<F>>;

    // All the column polynomials (including precommitted columns) evaluated in a point
    // Self::Evaluations::to_vec should return evaluations in the order consistent to Self::columns
    fn columns_evaluated(&self, zeta: &F) -> Self::Evaluations;

    // Constraint polynomials in evaluation form.
    fn constraints(&self) -> Vec<Evaluations<F>>;

    // 'Linearized' parts of constraint polynomials.
    // For a constraint of the form C = C(c1(X),...,ck(X),c1(wX),...,ck(wX)), where ci's are of degree n,
    // and an evaluation point z, it is a degree n polynomial r = C(c1(z),...,ck(z),c1(X),...,ck(X)).
    fn constraints_lin(&self, zeta: &F) -> Vec<DensePolynomial<F>>;

    // Subgroup over which the columns are defined.
    fn domain(&self) -> &Domain<F>;

    // The result of the computation.
    fn result(&self) -> Self::Instance;
}

pub trait VerifierPiop<F: PrimeField, C: Commitment<F>> {
    const N_CONSTRAINTS: usize;
    const N_COLUMNS: usize;
    // Columns the commitments to which are publicly known. These commitments are omitted from the proof.
    fn precommitted_columns(&self) -> Vec<C>;

    // Constant terms of the linearization polynomials for each constraint.
    fn evaluate_constraints_main(&self) -> Vec<F>;

    // Computes the constant term of the aggregated linearization polynomial
    // from the column evaluations at `zeta`.
    fn _evaluate_lin_poly_ct(&self, agg_coeffs: &[F]) -> F {
        self.evaluate_constraints_main()
            .iter()
            .zip(agg_coeffs)
            .map(|(c, alpha)| *alpha * c)
            .sum()
    }

    // Computes the quotient polynomial of the constraint system
    // from the column evaluations at `zeta` and the value of the linearization poly at `zeta.omega`.
    fn evaluate_q_at_zeta(&self, agg_coeffs: &[F], lin_at_zeta_omega: F) -> F {
        let eval: F = self._evaluate_lin_poly_ct(agg_coeffs);
        self.domain_evaluated()
            .divide_by_vanishing_poly_in_zeta(eval + lin_at_zeta_omega)
    }

    // Commitment to the aggregated linearization polynomial without the constant term.
    fn lin_poly_commitment(&self, agg_coeffs: &[F]) -> (Vec<F>, Vec<C>);

    fn domain_evaluated(&self) -> &EvaluatedDomain<F>;
}
