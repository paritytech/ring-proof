use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::{ColumnsCommited, ColumnsEvaluated};

pub mod params;
pub mod prover;
pub mod verifier;

type PiopProof<C> = w3f_plonk_common::PiopProof<
    <C as PrimeGroup>::ScalarField,
    WrappedAffine<C>,
    ProofComms<C>,
    ProofEvals<<C as PrimeGroup>::ScalarField>,
>;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofComms<C: CurveGroup> {
    pub(crate) node_idx: WrappedAffine<C>,
    pub(crate) bf_bits: WrappedAffine<C>,
    pub(crate) selected_node_acc: WrappedAffine<C>,
    pub(crate) blinded_node_acc: [WrappedAffine<C>; 2],
    pub(crate) node_idx_sum_acc: WrappedAffine<C>,
}

impl<C: CurveGroup> ColumnsCommited<C::ScalarField, WrappedAffine<C>> for ProofComms<C> {
    fn to_vec(self) -> Vec<WrappedAffine<C>> {
        self.into()
    }
}

impl<C: CurveGroup> From<ProofComms<C>> for Vec<WrappedAffine<C>> {
    fn from(value: ProofComms<C>) -> Self {
        let [blinded_node_acc_x, blinded_node_acc_y] = value.blinded_node_acc;
        vec![
            value.node_idx,
            value.bf_bits,
            value.selected_node_acc,
            blinded_node_acc_x,
            blinded_node_acc_y,
            value.node_idx_sum_acc,
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

impl<F: PrimeField> From<ProofEvals<F>> for Vec<F> {
    fn from(value: ProofEvals<F>) -> Self {
        vec![
            value.x_coords,
            value.h_powers[0],
            value.h_powers[1],
            value.node_idx,
            value.bf_bits,
            value.selected_node_acc,
            value.blinded_node_acc[0],
            value.blinded_node_acc[1],
            value.node_idx_sum_acc,
        ]
    }
}

impl<F: PrimeField> ColumnsEvaluated<F> for ProofEvals<F> {
    fn to_vec(self) -> Vec<F> {
        self.into()
    }
}
