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
    pub(crate) node_idx: C,
    pub(crate) bf_bits: C,
    pub(crate) selected_node_acc: C,
    pub(crate) blinded_node_acc: [C; 2],
    pub(crate) node_idx_sum_acc: C,
    pub(crate) phantom: PhantomData<F>,
}

impl<F: PrimeField, C: Commitment<F>> ColumnsCommited<F, C> for ProofComms<F, C> {
    fn to_vec(self) -> Vec<C> {
        vec![
            self.node_idx,
            self.bf_bits,
            self.selected_node_acc,
            self.blinded_node_acc[0].clone(),
            self.blinded_node_acc[1].clone(),
            self.node_idx_sum_acc,
        ]
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofEvals<F: PrimeField> {
    pub(crate) x_coords: F,
    pub(crate) h_powers: [F; 2],
    pub(crate) node_idx: F,
    pub(crate) bf_bits: F,
    pub(crate) selected_node_acc: F,
    pub(crate) blinded_node_acc: [F; 2],
    pub(crate) node_idx_sum_acc: F,
}

impl<F: PrimeField> ColumnsEvaluated<F> for ProofEvals<F> {
    fn to_vec(self) -> Vec<F> {
        vec![
            self.x_coords,
            self.h_powers[0],
            self.h_powers[1],
            self.node_idx,
            self.bf_bits,
            self.selected_node_acc,
            self.blinded_node_acc[0],
            self.blinded_node_acc[1],
            self.node_idx_sum_acc,
        ]
    }
}
