use crate::domain::{Domain, EvaluatedDomain};
use crate::piop::{ProverPiop, VerifierPiop};
use crate::{ColumnsCommited, ColumnsEvaluated};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Evaluations;
use std::marker::PhantomData;
use w3f_pcs::pcs::Commitment;

impl<F: PrimeField, C: Commitment<F>, CC: ColumnsCommited<F, C>, const K: usize>
    ColumnsCommited<F, C> for [CC; K]
{
    fn to_vec(self) -> Vec<C> {
        self.into_iter().flat_map(|p| p.to_vec()).collect()
    }
}

// TODO: remove
// TODO: fixed columns that are fixed (selectors) don't have to be re-evaluated in the same point.
// TODO: other columns (like root layer) can be just witnessed in the proof.
// Flattens the vec while moving the first 3 elements of each inner vec to the beginning of the vec.
fn excerpt_fixed_columns<T: Clone>(column_vecs: Vec<Vec<T>>) -> Vec<T> {
    let k = column_vecs.len();
    let total_cols = 9;
    let fixed_cols = 3;
    let advice_cols = total_cols - fixed_cols;
    let mut fixed = Vec::with_capacity(fixed_cols * k);
    let mut advice = Vec::with_capacity(advice_cols * k);
    for mut vec in column_vecs {
        assert_eq!(vec.len(), total_cols);
        advice.extend(vec.split_off(3));
        fixed.extend(vec);
    }
    [fixed, advice].concat()
}

impl<F: PrimeField, CE: ColumnsEvaluated<F>, const K: usize> ColumnsEvaluated<F> for [CE; K] {
    fn to_vec(self) -> Vec<F> {
        let column_vecs = self
            .iter()
            .map(|evals| evals.clone().to_vec())
            .collect::<Vec<_>>();
        let res = excerpt_fixed_columns(column_vecs);
        let total_cols = 9;
        debug_assert_eq!(res.len(), total_cols * K);
        res
    }
}

pub struct BatchProver<F: PrimeField, C: Commitment<F>, P: ProverPiop<F, C>, const K: usize>(
    pub [P; K],
    pub PhantomData<F>,
    pub PhantomData<C>,
);
pub struct BatchVerifier<F: PrimeField, C: Commitment<F>, V: VerifierPiop<F, C>, const K: usize>(
    pub [V; K],
    pub PhantomData<F>,
    pub PhantomData<C>,
);

impl<F: PrimeField, C: Commitment<F>, P: ProverPiop<F, C>, const K: usize> ProverPiop<F, C>
    for BatchProver<F, C, P, K>
{
    const N_COLUMNS: usize = P::N_COLUMNS * K;
    const N_CONSTRAINTS: usize = P::N_CONSTRAINTS * K;
    const N_QUOTIENT_CHUNKS: usize = P::N_QUOTIENT_CHUNKS;
    type Commitments = [P::Commitments; K];
    type Evaluations = [P::Evaluations; K];
    type Instance = [P::Instance; K];

    fn committed_columns<Fun: Fn(&DensePolynomial<F>) -> C + Clone>(
        &self,
        commit: Fun,
    ) -> Self::Commitments {
        self.0
            .iter()
            .map(|p| p.committed_columns(commit.clone()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn columns(&self) -> Vec<DensePolynomial<F>> {
        let column_vecs = self.0.iter().map(|p| p.columns()).collect::<Vec<_>>();
        excerpt_fixed_columns(column_vecs)
    }

    fn columns_evaluated(&self, zeta: &F) -> Self::Evaluations {
        self.0
            .iter()
            .map(|p| p.columns_evaluated(zeta))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        self.0.iter().flat_map(|p| p.constraints()).collect()
    }

    fn constraints_lin(&self, zeta: &F) -> Vec<DensePolynomial<F>> {
        self.0
            .iter()
            .flat_map(|p| p.constraints_lin(zeta))
            .collect()
    }

    fn quotient(&self, alphas: &[F]) -> Option<Vec<DensePolynomial<F>>> {
        self._quotient_chunks(alphas)
    }

    fn domain(&self) -> &Domain<F> {
        self.0[0].domain()
    }

    fn result(&self) -> Self::Instance {
        self.0
            .iter()
            .map(|p| p.result())
            .collect::<Vec<_>>() // Requires allocation if you use .collect()
            .try_into()
            .unwrap()
    }
}

impl<F: PrimeField, C: Commitment<F>, V: VerifierPiop<F, C>, const K: usize> VerifierPiop<F, C>
    for BatchVerifier<F, C, V, K>
{
    const N_COLUMNS: usize = V::N_COLUMNS * K;
    const N_CONSTRAINTS: usize = V::N_CONSTRAINTS * K;

    fn precommitted_columns(&self) -> Vec<C> {
        self.0
            .iter()
            .flat_map(|p| p.precommitted_columns())
            .collect()
    }

    fn evaluate_constraints_main(&self) -> Vec<F> {
        self.0
            .iter()
            .flat_map(|p| p.evaluate_constraints_main())
            .collect()
    }

    fn lin_poly_commitment(&self, agg_coeffs: &[F]) -> (Vec<F>, Vec<C>) {
        self.0
            .iter()
            .zip(agg_coeffs.chunks(V::N_CONSTRAINTS))
            .map(|(p, alphas)| p.lin_poly_commitment(alphas))
            .reduce(|(mut acc_f, mut acc_c), (f, c)| {
                acc_f.extend(f);
                acc_c.extend(c);
                (acc_f, acc_c)
            })
            .unwrap()
    }

    fn domain_evaluated(&self) -> &EvaluatedDomain<F> {
        self.0[0].domain_evaluated()
    }
}
