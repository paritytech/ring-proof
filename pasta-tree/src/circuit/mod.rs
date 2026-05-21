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
    pub(crate) node_selector: C,
    pub(crate) bf_bits: C,
    pub(crate) node_x_coord_acc: C,
    pub(crate) blinded_node_acc: [C; 2],
    pub(crate) phantom: PhantomData<F>,
}

impl<F: PrimeField, C: Commitment<F>> ColumnsCommited<F, C> for ProofComms<F, C> {
    fn to_vec(self) -> Vec<C> {
        vec![
            self.node_selector,
            self.bf_bits,
            self.node_x_coord_acc,
            self.blinded_node_acc[0].clone(),
            self.blinded_node_acc[1].clone(),
        ]
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofEvals<F: PrimeField> {
    pub(crate) x_coords: F,
    pub(crate) h_powers: [F; 2],
    pub(crate) node_selector: F,
    pub(crate) bf_bits: F,
    pub(crate) node_x_coord_acc: F,
    pub(crate) blinded_node_acc: [F; 2],
}

impl<F: PrimeField> ColumnsEvaluated<F> for ProofEvals<F> {
    fn to_vec(self) -> Vec<F> {
        vec![
            self.x_coords,
            self.h_powers[0],
            self.h_powers[1],
            self.node_selector,
            self.bf_bits,
            self.node_x_coord_acc,
            self.blinded_node_acc[0],
            self.blinded_node_acc[1],
        ]
    }
}
