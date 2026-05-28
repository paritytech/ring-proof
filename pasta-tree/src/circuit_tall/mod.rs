use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::piop::{ProverPiop, VerifierPiop};
use w3f_plonk_common::{ColumnsCommited, ColumnsEvaluated};

pub mod params;
pub mod prover;
pub mod verifier;

// struct SideProofParams<C: CurveGroup> {
//     _phantom: PhantomData<C>
// }
//
// impl <C: CurveGroup> GenericProofParams<C> for SideProofParams<C> {
//     type Cols = ProofComms<C>;
//     type Evals = ProofEvals<C::ScalarField>;
// }
//
// pub type LevelProof<C> = PiopProof<
//     <C as PrimeGroup>::ScalarField,
//     WrappedAffine<C>,
//     ProofComms<C>,
//     ProofEvals<<C as PrimeGroup>::ScalarField>,
// >;

/// The circuit is over `C::ScalarField`.
pub trait CircuitParams<C: CurveGroup> {
    type Witness;
    type Instance;
    type Proof;
    type ProverCircuit: ProverPiop<C::ScalarField, WrappedAffine<C>>;
    type VerifierCircuit: VerifierPiop<C::ScalarField, WrappedAffine<C>>;

    fn prover_circuit(&self, w: Self::Witness) -> Self::ProverCircuit;

    fn verifier_circuit(&self,
                        instance: Self::Instance,
                        fixed_cols: &[WrappedAffine<C>],
                        proof: Self::Proof,
                        zeta: C::ScalarField) -> Self::VerifierCircuit;
}

type PiopProof<C> = w3f_plonk_common::PiopProof<
    <C as PrimeGroup>::ScalarField,
    WrappedAffine<C>,
    ProofComms<C>,
    ProofEvals<<C as PrimeGroup>::ScalarField>
>;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofComms<C: CurveGroup> {
    /// Witnessed Y-coordinates of the point vector `nodes || h_powers` TODO: last 4 elements
    pub(crate) points_y: WrappedAffine<C>, // aka y_parent
    /// 0/1 vector `node_idx || bl`
    pub(crate) bits: WrappedAffine<C>,
    /// Inner product gadget accumulator
    pub(crate) inn_prod_acc: WrappedAffine<C>,
    /// EC addition (= fixed point multiplication) gadget accumulator
    pub(crate) cond_add_acc: [WrappedAffine<C>; 2],
}

impl<C: CurveGroup> ColumnsCommited<C::ScalarField, WrappedAffine<C>> for ProofComms<C> {
    fn to_vec(self) -> Vec<WrappedAffine<C>> {
        self.into()
    }
}

impl<C: CurveGroup> From<ProofComms<C>> for Vec<WrappedAffine<C>> {
    fn from(value: ProofComms<C>) -> Self {
        let [cond_add_acc_x, cond_add_acc_y] = value.cond_add_acc;
        vec![
            value.points_y,
            value.bits,
            value.inn_prod_acc,
            cond_add_acc_x,
            cond_add_acc_y,
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

impl<F: PrimeField> From<ProofEvals<F>> for Vec<F> {
    fn from(value: ProofEvals<F>) -> Self {
        value.to_vec()
    }
}
