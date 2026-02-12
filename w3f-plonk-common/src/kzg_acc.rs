use crate::piop::VerifierPiop;
use crate::verifier::Challenges;
use crate::{ColumnsCommited, ColumnsEvaluated, Proof};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_std::rand::Rng;
use ark_std::vec;
use ark_std::vec::Vec;
use w3f_pcs::pcs::kzg::params::KzgVerifierKey;
use w3f_pcs::pcs::kzg::{AccumulatedOpening, KZG};
use w3f_pcs::pcs::PCS;

// Accumulates KZG openning claims for Plonk proofs.
// Somewhat similar to https://eprint.iacr.org/2020/499.pdf, section 8.
// With a difference that this accumulates opennings lazily,
// and runs `2` MSMs of size `O(k)` at the final stage,
// that gives an asymptotic saving (thanks to Pippenger)
// at the cost of linear accumulator size.

pub struct KzgAccumulator<E: Pairing> {
    // acc_points[0] = G1
    acc_points: Vec<E::G1Affine>,
    // acc_scalars[0] = 0
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

    // `p(z) = v <=> q(X) = p(X)-v / X-z <=> q(X)(X-z) = p(X)-v <=> q(X)X = p(X) + q(X)z - v`.
    // Raising
    // `p(X) -> p(tau)G1 =: C`,
    // `q(X) -> q(tau)G1 =: pi`,
    // `X -> tau.G2`,
    // `v -> v.G1`,
    // and taking the pairing gives:
    // `e(pi, tau.G2) + e(C + z.pi - v.G1, -G2) = 0`.

    // Combining `k` such equations using random coefficients `ri` results in
    // `e(agg_pi, tau.G2) + e(acc, -G2) = 0`, where

    // `agg_pi := r1.pi_1 + ... + rk.pi_k` and

    // `acc := sum[r1.(C1 + z1.pi_1 - v1.G1), i = 1,...,k] =
    //  = -(r1.v1 + ... + rk.vk).G1 + (r1.C1 + ... + rk.Ck) + (r1.z1.pi_1 + ... + rk.zk.pi_k)`.

    // `agg_pi` is a `k`-MSM.
    // In a common case when a batch proof `pi_i` attests opennings of multiple (`ni`) commitments at the same point `zi`,
    // `Ci = ai_1.Ci_1 + ... + ai_ni.Ci_ni, i = 1,...,k`,
    // `acc` is a `1+k+(n1+...+nk)`-MSM.

    /// Accumulates
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
        let r = F::rand(rng);
        let r2 = r.square();
        let zeta = challenges.zeta;

        // TODO: it could be a method unless `to_vec(self)`
        let q_zeta = piop.evaluate_q_at_zeta(&challenges.alphas, proof.lin_at_zeta_omega);
        let mut columns_at_zeta = proof.columns_at_zeta.to_vec();
        columns_at_zeta.push(q_zeta);
        let agg_at_zeta: F = columns_at_zeta
            .into_iter()
            .zip(challenges.nus.iter())
            .map(|(y, r)| y * r)
            .sum();

        let zeta_omega = zeta * piop.domain_evaluated().omega();
        let lin_comm = piop.lin_poly_commitment(&challenges.alphas);

        // Openning at `z`
        // TODO: try to get rid of the commitment wrapper in flonk
        self.acc_points.extend(
            piop.precommitted_columns()
                .iter()
                .map(|c| c.0)
                .collect::<Vec<_>>(),
        );
        self.acc_points.extend(
            proof
                .column_commitments
                .to_vec()
                .iter()
                .map(|c| c.0)
                .collect::<Vec<_>>(),
        );
        self.acc_points.push(proof.quotient_commitment.clone().0);
        self.acc_scalars
            .extend(challenges.nus.iter().map(|nu| *nu * r).collect::<Vec<_>>()); // numbers should match here

        self.acc_points.push(proof.agg_at_zeta_proof);
        self.acc_scalars.push(zeta * r);
        self.acc_scalars[0] -= agg_at_zeta * r;

        // Openning at `z.w`
        // TODO: see above
        self.acc_points
            .extend(lin_comm.1.iter().map(|c| c.0).collect::<Vec<_>>());
        self.acc_scalars
            .extend(lin_comm.0.into_iter().map(|c| c * r2).collect::<Vec<_>>());
        self.acc_points.push(proof.lin_at_zeta_omega_proof);
        self.acc_scalars.push(zeta_omega * r2);
        self.acc_scalars[0] -= proof.lin_at_zeta_omega * r2;

        self.kzg_proofs.push(proof.agg_at_zeta_proof);
        self.kzg_proofs.push(proof.lin_at_zeta_omega_proof);
        self.randomizers.push(r);
        self.randomizers.push(r2);
    }

    pub fn verify(&self) -> bool {
        let proof = E::G1::msm(&self.kzg_proofs, &self.randomizers)
            .unwrap()
            .into_affine();
        if !crate::is_in_correct_subgroup_assuming_on_curve::<E>(&proof) {
            return false;
        }
        let acc = (-E::G1::msm(&self.acc_points, &self.acc_scalars).unwrap()).into_affine();
        if !crate::is_in_correct_subgroup_assuming_on_curve::<E>(&acc) {
            return false;
        }
        KZG::<E>::verify_accumulated(AccumulatedOpening { acc, proof }, &self.kzg_vk)
    }
}
