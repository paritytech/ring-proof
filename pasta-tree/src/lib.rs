pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use ark_std::rand::Rng;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use w3f_pcs::pcs::ipa::IPA;
    use w3f_plonk_common::test_helpers::random_vec;
    use w3f_ring_proof::ring_prover::RingProver;
    use w3f_ring_proof::{index, test_setup, ArkTranscript};
    use w3f_ring_proof::ring_verifier::RingVerifier;

    #[test]
    fn test_pasta_ring() {
        let rng = &mut test_rng();

        let (pcs_params, piop_params) = test_setup::<_, _, IPA<ark_pallas::Projective>, ark_vesta::VestaConfig>(rng, 512);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<ark_vesta::Affine, _>(keyset_size, rng);
        let (prover_key, verifier_key) = index::<_, IPA<ark_pallas::Projective>, _>(&pcs_params, &piop_params, &pks);

        let t_prove = start_timer!(|| "Prove");
        let prover_idx = rng.gen_range(0..keyset_size);
        let prover = RingProver::init(
            prover_key.clone(),
            piop_params.clone(),
            prover_idx,
            ArkTranscript::new(b"w3f-ring-proof-test"),
        );
        let prover_pk = pks[prover_idx].clone();
        let blinding_factor = ark_vesta::Fr::rand(rng);
        let blinded_pk = prover_pk + piop_params.h * blinding_factor;
        let blinded_pk = blinded_pk.into_affine();
        let proof = prover.prove(blinding_factor);
        end_timer!(t_prove);

        let ring_verifier = RingVerifier::init(
            verifier_key,
            piop_params,
            ArkTranscript::new(b"w3f-ring-proof-test"),
        );
        let t_verify = start_timer!(|| "Verify");
        assert!(ring_verifier.verify(proof, blinded_pk));
        end_timer!(t_verify);
    }
}
