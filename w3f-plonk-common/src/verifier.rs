use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::{Commitment, PcsParams, PCS};

use crate::piop::VerifierPiop;
use crate::transcript::PlonkTranscript;
use crate::{q_chunking, ColumnsCommited, ColumnsEvaluated, PiopProof, Proof};

pub struct PlonkVerifier<F: PrimeField, CS: PCS<F>, T: PlonkTranscript<F, CS>> {
    // Polynomial commitment scheme verifier's key.
    pub pcs_vk: CS::VK,
    // Transcript,
    // initialized with the public parameters and the commitments to the precommitted columns.
    pub transcript_prelude: T,
}

pub struct PcsOpeningAt2Points<F: PrimeField, C: Commitment<F>> {
    pub open_at_zeta: Vec<C>,
    pub open_at_zeta_omega: Vec<C>,
    pub zeta: F,
    pub zeta_omega: F,
    pub vals_at_zeta: Vec<F>,
    pub vals_at_zeta_omega: Vec<F>,
}

impl<F: PrimeField, CS: PCS<F>, T: PlonkTranscript<F, CS>> PlonkVerifier<F, CS, T> {
    pub fn init(
        pcs_vk: <CS::Params as PcsParams>::VK,
        verifier_key: &impl CanonicalSerialize,
        empty_transcript: T,
    ) -> Self {
        let mut transcript_prelude = empty_transcript;
        transcript_prelude._add_serializable(b"vk", verifier_key);

        Self {
            pcs_vk,
            transcript_prelude,
        }
    }

    pub fn evaluate_piop<Piop, Commitments, Evaluations>(
        &self,
        piop: Piop,
        proof: PiopProof<F, CS::C, Commitments, Evaluations>,
        challenges: Challenges<F>,
    ) -> PcsOpeningAt2Points<F, CS::C>
    where
        Piop: VerifierPiop<F, CS::C>,
        Commitments: ColumnsCommited<F, CS::C>,
        Evaluations: ColumnsEvaluated<F>,
    {
        let mut open_at_zeta = piop.precommitted_columns();
        open_at_zeta.extend(proof.column_commitments.to_vec());
        // q(X) = q0(X) + q1(X)X^n + q2(X)X^{2n} (+ ... + qk(X)X^{kn})
        // Let q_z(X) = q0(X) + q1(X).z^n + q2(X).z^{2n}
        // then q_z(z) = q(z)
        let quotient_commitment =
            q_chunking::compose_quotient(&proof.quotient_chunks, piop.domain_evaluated().z_n);
        open_at_zeta.push(quotient_commitment);

        let mut vals_at_zeta = proof.columns_at_zeta.to_vec();
        let q_zeta = piop.evaluate_q_at_zeta(&challenges.alphas, proof.lin_at_zeta_omega);
        vals_at_zeta.push(q_zeta);

        let lin_comm = piop.lin_poly_commitment(&challenges.alphas);
        let lin_comm = CS::C::combine(&lin_comm.0, &lin_comm.1);

        let zeta = challenges.zeta;
        let zeta_omega = zeta * piop.domain_evaluated().omega();

        PcsOpeningAt2Points {
            open_at_zeta,
            open_at_zeta_omega: vec![lin_comm],
            zeta,
            zeta_omega,
            vals_at_zeta,
            vals_at_zeta_omega: vec![proof.lin_at_zeta_omega],
        }
    }

    pub fn verify<Piop, Commitments, Evaluations, R: Rng>(
        &self,
        piop: Piop,
        proof: Proof<F, CS, Commitments, Evaluations>,
        challenges: Challenges<F>,
        rng: &mut R,
    ) -> bool
    where
        Piop: VerifierPiop<F, CS::C>,
        Commitments: ColumnsCommited<F, CS::C>,
        Evaluations: ColumnsEvaluated<F>,
    {
        let piop_proof = proof.to_piop_proof();
        let PcsOpeningAt2Points {
            open_at_zeta,
            open_at_zeta_omega,
            zeta,
            zeta_omega,
            vals_at_zeta,
            vals_at_zeta_omega,
        } = self.evaluate_piop(piop, piop_proof, challenges.clone());

        let agg_comm = CS::C::combine(&challenges.nus, &open_at_zeta);
        let agg_at_zeta = vals_at_zeta
            .into_iter()
            .zip(challenges.nus.iter())
            .map(|(y, r)| y * r)
            .sum();
        let lin_comm = open_at_zeta_omega[0].clone();
        let lin_at_zeta_omega = vals_at_zeta_omega[0];

        CS::batch_verify(
            &self.pcs_vk,
            vec![agg_comm, lin_comm],
            vec![zeta, zeta_omega],
            vec![agg_at_zeta, lin_at_zeta_omega],
            vec![proof.agg_at_zeta_proof, proof.lin_at_zeta_omega_proof],
            rng,
        )
        .is_ok()
    }

    pub fn restore_challenges<Commitments, Evaluations>(
        &self,
        instance: &impl CanonicalSerialize,
        proof: &PiopProof<F, CS::C, Commitments, Evaluations>,
        n_polys: usize,
        n_constraints: usize,
    ) -> (Challenges<F>, T)
    where
        Commitments: ColumnsCommited<F, CS::C>,
        Evaluations: ColumnsEvaluated<F>,
    {
        let mut transcript = self.transcript_prelude.clone();
        transcript.add_instance(instance);
        transcript.add_committed_cols(&proof.column_commitments);
        // let r = transcript.get_bitmask_aggregation_challenge();
        // transcript.append_2nd_round_register_commitments(&proof.additional_commitments);
        let alphas = transcript.get_constraints_aggregation_coeffs(n_constraints);
        for quotient_chunk in proof.quotient_chunks.iter() {
            transcript.add_quotient_commitment(quotient_chunk);
        }
        let zeta = transcript.get_evaluation_point();
        transcript.add_evaluations(&proof.columns_at_zeta, &proof.lin_at_zeta_omega);
        let nus = transcript.get_kzg_aggregation_challenges(n_polys);
        let challenges = Challenges { alphas, zeta, nus };
        (challenges, transcript)
    }
}

#[derive(Clone)]
pub struct Challenges<F: Field> {
    pub alphas: Vec<F>,
    pub zeta: F,
    pub nus: Vec<F>,
}
