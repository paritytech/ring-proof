#![cfg_attr(not(feature = "std"), no_std)]

use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{FftField, Field, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::{Commitment, PCS};

pub mod domain;
pub mod gadgets;
pub mod kzg_acc;
pub mod piop;
pub mod prover;
pub mod test_helpers;
pub mod transcript;
pub mod verifier;

pub trait Column<F: FftField> {
    /// Type of a column cell.
    type T;
    /// Evaluation domain of the associated column polynomial `p`:
    /// `p(w^i) = col[i]` for the domain generator `w`.
    fn domain(&self) -> GeneralEvaluationDomain<F>;
    /// Evaluation domain of constraint polynomials.
    fn domain_4x(&self) -> GeneralEvaluationDomain<F>;
    /// Length of the constrained prefix of the column.
    /// Is either equal to `domain.capacity` or `domain.capacity - 1`.
    fn constrained_len(&self) -> usize;
    /// Values of the cells that are constrained.
    fn constrained_vals(&self) -> &[Self::T];
}

// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[derive(Clone)]
pub struct FieldColumn<F: FftField> {
    constrained_len: usize,
    pub poly: DensePolynomial<F>,
    pub evals: Evaluations<F>,
    pub evals_4x: Evaluations<F>,
}

impl<F: FftField> FieldColumn<F> {
    pub fn shifted_4x(&self) -> Evaluations<F> {
        let mut evals_4x = self.evals_4x.evals.clone();
        evals_4x.rotate_left(4);
        Evaluations::from_vec_and_domain(evals_4x, self.domain_4x())
    }

    pub fn as_poly(&self) -> &DensePolynomial<F> {
        &self.poly
    }

    pub fn evaluate(&self, z: &F) -> F {
        self.poly.evaluate(z)
    }
}

impl<F: FftField> Column<F> for FieldColumn<F> {
    type T = F;

    fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.evals.domain()
    }

    fn domain_4x(&self) -> GeneralEvaluationDomain<F> {
        self.evals_4x.domain()
    }

    fn constrained_len(&self) -> usize {
        self.constrained_len
    }

    fn constrained_vals(&self) -> &[Self::T] {
        &self.evals.evals[..self.constrained_len]
    }
}

pub fn const_evals<F: FftField>(c: F, domain: GeneralEvaluationDomain<F>) -> Evaluations<F> {
    Evaluations::from_vec_and_domain(vec![c; domain.size()], domain)
}

pub trait ColumnsEvaluated<F: PrimeField>: CanonicalSerialize + CanonicalDeserialize {
    fn to_vec(self) -> Vec<F>;
}

pub trait ColumnsCommited<F: PrimeField, C: Commitment<F>>:
    CanonicalSerialize + CanonicalDeserialize
{
    fn to_vec(self) -> Vec<C>;
}

// suboptimal for BLS12-381
fn is_in_correct_subgroup_assuming_on_curve<E: Pairing>(p: &E::G1Affine) -> bool {
    let r = E::ScalarField::characteristic();
    p.mul_bigint(r).is_zero()
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F, CS, Commitments, Evaluations>
where
    F: PrimeField,
    CS: PCS<F>,
    Commitments: ColumnsCommited<F, CS::C>,
    Evaluations: ColumnsEvaluated<F>,
{
    pub column_commitments: Commitments,
    pub columns_at_zeta: Evaluations,
    pub quotient_commitment: CS::C,
    pub lin_at_zeta_omega: F,
    pub agg_at_zeta_proof: CS::Proof,
    pub lin_at_zeta_omega_proof: CS::Proof,
}
