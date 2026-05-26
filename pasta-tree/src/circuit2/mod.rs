use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::Commitment;
use w3f_plonk_common::{ColumnsCommited, ColumnsEvaluated};

pub mod params;
pub mod prover;
pub mod verifier;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofComms<F: PrimeField, C: Commitment<F>> {
    pub(crate) points_y: C,
    pub(crate) bits: C,
    pub(crate) inn_prod_acc: C,
    pub(crate) cond_add_acc: [C; 2],
    pub(crate) phantom: PhantomData<F>,
}

impl<F: PrimeField, C: Commitment<F>> ColumnsCommited<F, C> for ProofComms<F, C> {
    fn to_vec(self) -> Vec<C> {
        vec![
            self.points_y,
            self.bits,
            self.inn_prod_acc,
            self.cond_add_acc[0].clone(),
            self.cond_add_acc[1].clone(),
        ]
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofEvals<F: PrimeField> {
    pub(crate) points: [F; 2],
    pub(crate) ring_selector: F,
    pub(crate) bits: F,
    pub(crate) inn_prod_acc: F,
    pub(crate) cond_add_acc: [F; 2],
}

impl<F: PrimeField> ColumnsEvaluated<F> for ProofEvals<F> {
    fn to_vec(self) -> Vec<F> {
        vec![
            self.points[0],
            self.ring_selector,
            self.points[1],
            self.bits,
            self.inn_prod_acc,
            self.cond_add_acc[0],
            self.cond_add_acc[1],
        ]
    }
}
