pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_poly::Polynomial;
    use ark_std::iterable::Iterable;
    use ark_std::rand::Rng;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use ark_vesta::VestaConfig;
    use std::collections::BTreeSet;
    use w3f_pcs::aggregation::multiple::Transcript;
    use w3f_pcs::pcs::ipa::IPA;
    use w3f_pcs::pcs::kzg::commitment::WrappedAffine;
    use w3f_pcs::pcs::{RawVerifierKey, PCS};
    use w3f_pcs::shplonk::Shplonk;
    use w3f_plonk_common::piop::ProverPiop;
    use w3f_plonk_common::prover::PlonkProver;
    use w3f_plonk_common::test_helpers::random_vec;
    use w3f_ring_proof::piop::prover::PiopProver;
    use w3f_ring_proof::ring_prover::RingProver;
    use w3f_ring_proof::ring_verifier::RingVerifier;
    use w3f_ring_proof::{index, test_setup, ArkTranscript};

    type PallasIPA = IPA<ark_pallas::Projective>;
    type PallasC = WrappedAffine<ark_pallas::Affine>;

    // cargo test test_pasta_ring_plonk --release --features="print-trace" -- --show-output
    #[test]
    fn test_pasta_ring_plonk() {
        let rng = &mut test_rng();

        // setup
        let domain_size = 2usize.pow(9);
        let (pcs_params, piop_params) = test_setup::<_, _, PallasIPA, VestaConfig>(rng, domain_size);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<ark_vesta::Affine, _>(keyset_size, rng);
        let (prover_key, verifier_key) = index::<_, PallasIPA, _>(&pcs_params, &piop_params, &pks);
        let blinding = ark_vesta::Fr::rand(rng);
        let pk_idx = rng.gen_range(0..keyset_size);
        let blinded_pk = piop_params.blind_pk(pks[pk_idx], blinding);

        // prover
        let fs = ArkTranscript::new(b"pasta-ring-proof-test");
        let prover = RingProver::init(prover_key, piop_params.clone(), 0, fs.clone());
        let t_prove = start_timer!(|| format!("Proving IPA ring-proof with plonk, domain_size={domain_size}, keyset_size={keyset_size}"));
        let (blinded_pk_, proof) = prover.rerandomize_pk(pk_idx, blinding);
        end_timer!(t_prove);
        assert_eq!(blinded_pk_, blinded_pk);

        // verifier
        let ring_verifier = RingVerifier::init(verifier_key, piop_params, fs);
        let t_verify = start_timer!(|| "Verifying IPA plonk opening");
        let valid = ring_verifier.verify(proof, blinded_pk);
        end_timer!(t_verify);
        assert!(valid);
    }

    struct Coeffs<F: PrimeField>(F, F);
    impl<F: PrimeField, CS: PCS<F>> Transcript<F, CS> for Coeffs<F> {
        fn get_gamma(&mut self) -> F {
            self.0
        }

        fn commit_to_q(&mut self, _q: &CS::C) {}

        fn get_zeta(&mut self) -> F {
            self.1
        }
    }

    // cargo test test_pasta_ring_shplonk --release --features="print-trace" -- --show-output
    #[test]
    fn test_pasta_ring_shplonk() {
        let rng = &mut test_rng();

        // setup
        let domain_size = 2usize.pow(9);
        let (pcs_params, piop_params) = test_setup::<_, _, PallasIPA, VestaConfig>(rng, domain_size);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<ark_vesta::Affine, _>(keyset_size, rng);
        let (prover_key, verifier_key) = index::<_, PallasIPA, _>(&pcs_params, &piop_params, &pks);
        let blinding = ark_vesta::Fr::rand(rng);
        let pk_idx = rng.gen_range(0..keyset_size);
        // let blinded_pk = {
        //     let prover_pk = pks[pk_idx].clone();
        //     let blinded_pk = prover_pk + piop_params.h * blinding;
        //     blinded_pk.into_affine()
        // };
        let pcs_ck = prover_key.pcs_ck;
        let pcs_vk = verifier_key.pcs_raw_vk.prepare();

        // prover
        let piop = PiopProver::<ark_pallas::Fr, VestaConfig>::build(&piop_params, prover_key.fixed_columns.clone(), pk_idx, blinding);
        let t_prove = start_timer!(|| format!("Proving IPA ring-proof with shplonk, domain_size={domain_size}, keyset_size={keyset_size}"));
        let zeta = ark_pallas::Fr::rand(rng);
        let columns = <PiopProver<_, _> as ProverPiop<ark_pallas::Fr, PallasC>>::columns(&piop);
        let (quotient, agg_lin) = {
            let constraints = <PiopProver<_, _> as ProverPiop<ark_pallas::Fr, PallasC>>::constraints(&piop);
            let alphas: Vec<_> = (0..constraints.len()).map(|_| ark_pallas::Fr::rand(rng)).collect();
            let agg_constraint_poly = PlonkProver::<ark_pallas::Fr, PallasIPA, ArkTranscript>::aggregate_evaluations(&constraints, &alphas).interpolate();
            let quotient = piop_params.domain.divide_by_vanishing_poly(&agg_constraint_poly);
            let constraints_lin = <PiopProver<_, _> as ProverPiop<ark_pallas::Fr, PallasC>>::constraints_lin(&piop, &zeta);
            let agg_lin = w3f_pcs::aggregation::single::aggregate_polys(&constraints_lin, &alphas);
            (quotient, agg_lin)
        };

        let mut polys = columns;
        polys.push(quotient);
        let mut coord_vecs = vec![vec![zeta]; polys.len()];
        polys.push(agg_lin.clone());
        coord_vecs.push(vec![zeta * piop_params.domain.omega()]);

        // commitments
        let mut poly_cs = verifier_key.fixed_columns_committed.as_vec();
        let t_commit = start_timer!(|| format!("Commiting to {} columns of degree = {} and the quotient  of degree = {}", polys.len()-5, polys[3].degree(), polys[7].degree()));
        // skip the instance columns and the linearirization polynomial `agg_lin`
        poly_cs.extend(polys[3..polys.len() - 1].iter().map(|p| PallasIPA::commit(&pcs_ck, p).unwrap()));
        end_timer!(t_commit);
        poly_cs.push(PallasIPA::commit(&pcs_ck, &agg_lin).unwrap());

        let coord_sets: Vec<BTreeSet<ark_pallas::Fr>> = coord_vecs.iter().cloned().map(BTreeSet::from_iter).collect();
        let vals: Vec<_> = polys.iter().zip(coord_vecs.iter())
            .map(|(f, xs)| xs.iter().map(|x| f.evaluate(&x)).collect::<Vec<_>>())
            .collect();

        let transcript = &mut Coeffs(ark_pallas::Fr::rand(rng), ark_pallas::Fr::rand(rng));
        let t_open = start_timer!(|| format!("Opening IPA ring-proof with shplonk, {} polys, max_degree = {}", polys.len(), polys[7].degree()));
        let proof = Shplonk::<ark_pallas::Fr, PallasIPA>::open_many(
            &pcs_ck,
            &polys,
            &coord_sets,
            transcript,
        );
        end_timer!(t_open);
        end_timer!(t_prove);

        // verifier
        let t_verify = start_timer!(|| "Verifying IPA shplonk opening");
        let valid = Shplonk::<ark_pallas::Fr, PallasIPA>::verify_many(
            &pcs_vk,
            &poly_cs,
            proof,
            &coord_vecs,
            &vals,
            transcript,
        );
        end_timer!(t_verify);
        assert!(valid);
    }
}
