use ark_ec::pairing::Pairing;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::kzg::commitment::KzgCommitment;
use w3f_pcs::pcs::kzg::params::RawKzgVerifierKey;
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::{Commitment, PcsParams, PCS};

pub(crate) use prover::PiopProver;
pub(crate) use verifier::PiopVerifier;
use w3f_plonk_common::gadgets::ec::AffineColumn;
use w3f_plonk_common::{ColumnsCommited, ColumnsEvaluated};

use crate::PiopParams;

mod cell_equality;
pub mod params;
mod prover;
mod verifier;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingCommitments<F: PrimeField, C: Commitment<F>> {
    // `pks` and `doublings_of_g` are prepended by the verifier
    pub(crate) sk_bits: C,
    pub(crate) pk_index: C,
    pub(crate) pk_from_sk: [C; 2],
    pub(crate) doublings_of_in: [C; 2],
    pub(crate) out_from_in: [C; 2],
    pub(crate) pk_from_index: [C; 2],
    pub(crate) pk_index_sum: C,
    pub(crate) phantom: PhantomData<F>,
}

impl<F: PrimeField, C: Commitment<F>> ColumnsCommited<F, C> for RingCommitments<F, C> {
    fn to_vec(self) -> Vec<C> {
        vec![
            self.sk_bits,
            self.pk_index,
            self.pk_from_sk[0].clone(),
            self.pk_from_sk[1].clone(),
            self.doublings_of_in[0].clone(),
            self.doublings_of_in[1].clone(),
            self.out_from_in[0].clone(),
            self.out_from_in[1].clone(),
            self.pk_from_index[0].clone(),
            self.pk_from_index[1].clone(),
            self.pk_index_sum.clone(),
        ]
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingEvaluations<F: PrimeField> {
    pub(crate) pks: [F; 2],
    pub(crate) doublings_of_g: [F; 2],
    pub(crate) sk_bits: F,
    pub(crate) pk_index: F,
    pub(crate) pk_from_sk: [F; 2],
    pub(crate) doublings_of_in: [F; 2],
    pub(crate) out_from_in: [F; 2],
    pub(crate) pk_from_index: [F; 2],
    pub(crate) pk_index_sum: F,
}

impl<F: PrimeField> ColumnsEvaluated<F> for RingEvaluations<F> {
    fn to_vec(self) -> Vec<F> {
        vec![
            self.pks[0],
            self.pks[1],
            self.doublings_of_g[0],
            self.doublings_of_g[1],
            self.sk_bits,
            self.pk_index,
            self.pk_from_sk[0],
            self.pk_from_sk[1],
            self.doublings_of_in[0],
            self.doublings_of_in[1],
            self.out_from_in[0],
            self.out_from_in[1],
            self.pk_from_index[0],
            self.pk_from_index[1],
            self.pk_index_sum,
        ]
    }
}

// Columns commitment to which the verifier knows (or trusts).
// TODO: comments
// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[derive(Clone)]
pub struct FixedColumns<F: PrimeField, G: AffineRepr<BaseField = F>> {
    pks: AffineColumn<F, G>,
    doublings_of_g: AffineColumn<F, G>,
}

// Commitments to the fixed columns (see above).
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Debug)]
pub struct FixedColumnsCommitted<F: PrimeField, C: Commitment<F>> {
    pub pks: [C; 2],
    pub doublings_of_g: [C; 2],
    pub phantom: PhantomData<F>,
}

impl<F: PrimeField, C: Commitment<F>> FixedColumnsCommitted<F, C> {
    fn as_vec(&self) -> Vec<C> {
        vec![
            self.pks[0].clone(),
            self.pks[1].clone(),
            self.doublings_of_g[0].clone(),
            self.doublings_of_g[1].clone(),
        ]
    }
}

// impl<E: Pairing> FixedColumnsCommitted<E::ScalarField, KzgCommitment<E>> {
//     pub fn from_ring<G: TECurveConfig<BaseField = E::ScalarField>>(
//         ring: &Ring<E::ScalarField, E, G>,
//     ) -> Self {
//         let cx = KzgCommitment(ring.cx);
//         let cy = KzgCommitment(ring.cy);
//         Self {
//             doublings_of_g: [cx, cy],
//             phantom: Default::default(),
//         }
//     }
// }

impl<F: PrimeField, G: AffineRepr<BaseField = F>> FixedColumns<F, G> {
    fn commit<CS: PCS<F>>(&self, ck: &CS::CK) -> FixedColumnsCommitted<F, CS::C> {
        let pks = [
            CS::commit(ck, self.pks.xs.as_poly()).unwrap(),
            CS::commit(ck, self.pks.ys.as_poly()).unwrap(),
        ];
        let doublings_of_g = [
            CS::commit(ck, self.doublings_of_g.xs.as_poly()).unwrap(),
            CS::commit(ck, self.doublings_of_g.ys.as_poly()).unwrap(),
        ];
        FixedColumnsCommitted {
            pks,
            doublings_of_g,
            phantom: Default::default(),
        }
    }
}

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverKey<F: PrimeField, CS: PCS<F>, G: AffineRepr<BaseField = F>> {
    pub(crate) pcs_ck: CS::CK,
    pub(crate) fixed_columns: FixedColumns<F, G>,
    pub(crate) verifier_key: VerifierKey<F, CS>, // used in the Fiat-Shamir transform
}

#[derive(Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierKey<F: PrimeField, CS: PCS<F>> {
    pub(crate) pcs_raw_vk: <CS::Params as PcsParams>::RVK,
    pub(crate) fixed_columns_committed: FixedColumnsCommitted<F, CS::C>,
    //TODO: domain
}

impl<E: Pairing> VerifierKey<E::ScalarField, KZG<E>> {
    // pub fn from_ring_and_kzg_vk<G: TECurveConfig<BaseField = E::ScalarField>>(
    //     ring: &Ring<E::ScalarField, E, G>,
    //     kzg_vk: RawKzgVerifierKey<E>,
    // ) -> Self {
    //     Self::from_commitment_and_kzg_vk(FixedColumnsCommitted::from_ring(ring), kzg_vk)
    // }

    pub fn from_commitment_and_kzg_vk(
        commitment: FixedColumnsCommitted<E::ScalarField, KzgCommitment<E>>,
        kzg_vk: RawKzgVerifierKey<E>,
    ) -> Self {
        Self {
            pcs_raw_vk: kzg_vk,
            fixed_columns_committed: commitment,
        }
    }

    pub fn commitment(&self) -> FixedColumnsCommitted<E::ScalarField, KzgCommitment<E>> {
        self.fixed_columns_committed.clone()
    }
}

pub fn index<F: PrimeField, CS: PCS<F>, Curve: TECurveConfig<BaseField = F>>(
    pcs_params: &CS::Params,
    piop_params: &PiopParams<F, Curve>,
    keys: &[Affine<Curve>],
) -> (ProverKey<F, CS, Affine<Curve>>, VerifierKey<F, CS>) {
    let pcs_ck = pcs_params.ck();
    let pcs_raw_vk = pcs_params.raw_vk();
    let fixed_columns = piop_params.fixed_columns(keys.to_vec()); //TODO
    let fixed_columns_committed = fixed_columns.commit::<CS>(&pcs_ck);
    let verifier_key = VerifierKey {
        pcs_raw_vk: pcs_raw_vk.clone(),
        fixed_columns_committed: fixed_columns_committed.clone(),
    };
    let prover_key = ProverKey {
        pcs_ck,
        fixed_columns,
        verifier_key,
    };
    let verifier_key = VerifierKey {
        pcs_raw_vk,
        fixed_columns_committed,
    };
    (prover_key, verifier_key)
}
