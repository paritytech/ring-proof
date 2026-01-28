use crate::piop::VerifierPiop;
use crate::verifier::Challenges;
use crate::{ColumnsCommited, ColumnsEvaluated, Proof};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_std::rand::Rng;
use w3f_pcs::pcs::kzg::params::KzgVerifierKey;
use w3f_pcs::pcs::kzg::{AccumulatedOpening, KZG};
use w3f_pcs::pcs::PCS;

// Aggregates opennings for KZG commitments.
// Somewhat similar to https://eprint.iacr.org/2020/499.pdf, section 8.
// With a difference that this accumulates opennings lazily,
// and runs `2` MSMs of size `O(n)` at the final stage,
// that gives an asymptotic saving (thanks to Pippenger)
// at the cost of linear accumulator size.
pub struct KzgAccumulator<E: Pairing> {
    acc_points: Vec<E::G1Affine>,
    acc_scalars: Vec<E::ScalarField>,
    kzg_proofs: Vec<E::G1Affine>,
    randomizers: Vec<E::ScalarField>,
    kzg_vk: KzgVerifierKey<E>,
}

impl<E: Pairing> KzgAccumulator<E> {
    pub fn new(kzg_vk: KzgVerifierKey<E>) -> Self {
        //TODO: capacity
        Self {
            acc_points: vec![kzg_vk.g1],
            acc_scalars: vec![E::ScalarField::zero()],
            kzg_proofs: vec![],
            randomizers: vec![],
            kzg_vk,
        }
    }

    pub fn accumulate<F, Piop, Commitments, Evaluations, R: Rng>(
        &mut self,
        piop: Piop,
        proof: Proof<F, KZG<E>, Commitments, Evaluations>,
        challenges: Challenges<F>,
        rng: &mut R,
    ) where
        F: PrimeField,
        E: Pairing<ScalarField = F>,
        Piop: VerifierPiop<F, <KZG<E> as PCS<F>>::C>,
        Commitments: ColumnsCommited<F, <KZG<E> as PCS<F>>::C>,
        Evaluations: ColumnsEvaluated<F>,
    {
        let q_zeta = piop.evaluate_q_at_zeta(&challenges.alphas, proof.lin_at_zeta_omega);

        let mut columns = [
            piop.precommitted_columns(),
            proof.column_commitments.to_vec(),
        ]
        .concat();
        columns.push(proof.quotient_commitment.clone());
        let columns = columns.iter().map(|c| c.0).collect::<Vec<_>>();

        let mut columns_at_zeta = proof.columns_at_zeta.to_vec();
        columns_at_zeta.push(q_zeta);

        let agg_at_zeta: F = columns_at_zeta
            .into_iter()
            .zip(challenges.nus.iter())
            .map(|(y, r)| y * r)
            .sum();

        let lin_comm = piop.lin_poly_commitment(&challenges.alphas);

        let zeta = challenges.zeta;
        let zeta_omega = zeta * piop.domain_evaluated().omega();

        let mut acc_points = vec![];
        let mut acc_scalars = vec![];

        acc_points.extend(columns);
        acc_scalars.extend(challenges.nus);
        acc_points.push(proof.agg_at_zeta_proof);
        acc_scalars.push(zeta);
        self.acc_scalars[0] -= agg_at_zeta;

        let r = F::rand(rng);
        // z.w openning
        acc_points.extend(lin_comm.1.iter().map(|c| c.0).collect::<Vec<_>>());
        acc_scalars.extend(lin_comm.0.into_iter().map(|c| c * r).collect::<Vec<_>>());
        acc_points.push(proof.lin_at_zeta_omega_proof);
        acc_scalars.push(zeta_omega * r);
        self.acc_scalars[0] -= proof.lin_at_zeta_omega * r;

        let kzg_proofs = vec![proof.agg_at_zeta_proof, proof.lin_at_zeta_omega_proof];
        let randomizers = vec![F::one(), r];

        self.acc_points.extend(acc_points);
        self.acc_scalars.extend(acc_scalars);
        self.kzg_proofs.extend(kzg_proofs);
        self.randomizers.extend(randomizers);
    }

    pub fn verify(&self) -> bool {
        let acc = (-E::G1::msm(&self.acc_points, &self.acc_scalars).unwrap()).into_affine();
        let proof = E::G1::msm(&self.kzg_proofs, &self.randomizers)
            .unwrap()
            .into_affine();
        KZG::<E>::verify_accumulated(AccumulatedOpening { acc, proof }, &self.kzg_vk)
    }
}
