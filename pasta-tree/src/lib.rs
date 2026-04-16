pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use ark_ec::AdditiveGroup;
    use ark_ec::scalar_mul::glv::GLVConfig;
    use ark_ec::scalar_mul::wnaf::WnafContext;
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_ff::{BigInteger, Field, Zero};
    use ark_pallas::PallasConfig;
    use ark_poly::DenseUVPolynomial;
    use ark_poly::Polynomial;
    use ark_std::iterable::Iterable;
    use ark_std::rand::Rng;
    use ark_std::{UniformRand, cfg_iter_mut, end_timer, start_timer, test_rng};
    use ark_vesta::VestaConfig;
    use std::collections::BTreeSet;
    use w3f_pcs::aggregation::multiple::Transcript;
    use w3f_pcs::pcs::PcsParams;
    use w3f_pcs::pcs::ipa::IPA;
    use w3f_pcs::pcs::kzg::commitment::WrappedAffine;
    use w3f_pcs::pcs::{PCS, RawVerifierKey};
    use w3f_pcs::shplonk::Shplonk;
    use w3f_plonk_common::piop::ProverPiop;
    use w3f_plonk_common::prover::PlonkProver;
    use w3f_plonk_common::test_helpers::random_vec;
    use w3f_ring_proof::piop::prover::PiopProver;
    use w3f_ring_proof::ring_prover::RingProver;
    use w3f_ring_proof::ring_verifier::RingVerifier;
    use w3f_ring_proof::{ArkTranscript, index, test_setup};

    #[cfg(feature = "parallel")]
    use rayon::prelude::*;
    use w3f_pcs::Poly;

    type PallasIPA = IPA<ark_pallas::Projective>;
    type PallasC = WrappedAffine<ark_pallas::Affine>;

    // cargo test test_pasta_ring_plonk --release --features="print-trace" -- --show-output
    #[test]
    fn test_pasta_ring_plonk() {
        let rng = &mut test_rng();

        // setup
        let domain_size = 2usize.pow(9);
        let (pcs_params, piop_params) =
            test_setup::<_, _, PallasIPA, VestaConfig>(rng, domain_size);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<ark_vesta::Affine, _>(keyset_size, rng);
        let (prover_key, verifier_key) = index::<_, PallasIPA, _>(&pcs_params, &piop_params, &pks);
        let blinding = ark_vesta::Fr::rand(rng);
        let pk_idx = rng.gen_range(0..keyset_size);
        let blinded_pk = piop_params.blind_pk(pks[pk_idx], blinding);

        // prover
        let fs = ArkTranscript::new(b"pasta-ring-proof-test");
        let prover = RingProver::init(prover_key, piop_params.clone(), 0, fs.clone());
        let t_prove = start_timer!(|| format!(
            "Proving IPA ring-proof with plonk, domain_size={domain_size}, keyset_size={keyset_size}"
        ));
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
        let (pcs_params, piop_params) =
            test_setup::<_, _, PallasIPA, VestaConfig>(rng, domain_size);
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
        let piop = PiopProver::<ark_pallas::Fr, VestaConfig>::build(
            &piop_params,
            prover_key.fixed_columns.clone(),
            pk_idx,
            blinding,
        );
        let t_prove = start_timer!(|| format!(
            "Proving IPA ring-proof with shplonk, domain_size={domain_size}, keyset_size={keyset_size}"
        ));
        let zeta = ark_pallas::Fr::rand(rng);
        let columns = <PiopProver<_, _> as ProverPiop<ark_pallas::Fr, PallasC>>::columns(&piop);
        let (quotient, agg_lin) = {
            let constraints =
                <PiopProver<_, _> as ProverPiop<ark_pallas::Fr, PallasC>>::constraints(&piop);
            let alphas: Vec<_> = (0..constraints.len())
                .map(|_| ark_pallas::Fr::rand(rng))
                .collect();
            let agg_constraint_poly =
                PlonkProver::<ark_pallas::Fr, PallasIPA, ArkTranscript>::aggregate_evaluations(
                    &constraints,
                    &alphas,
                )
                .interpolate();
            let quotient = piop_params
                .domain
                .divide_by_vanishing_poly(&agg_constraint_poly);
            let constraints_lin =
                <PiopProver<_, _> as ProverPiop<ark_pallas::Fr, PallasC>>::constraints_lin(
                    &piop, &zeta,
                );
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
        let t_commit = start_timer!(|| format!(
            "Commiting to {} columns of degree = {} and the quotient of degree = {}",
            polys.len() - 5,
            polys[3].degree(),
            polys[7].degree()
        ));
        // skip the instance columns and the linearirization polynomial `agg_lin`
        poly_cs.extend(
            polys[3..polys.len() - 1]
                .iter()
                .map(|p| PallasIPA::commit(&pcs_ck, p).unwrap()),
        );
        end_timer!(t_commit);
        poly_cs.push(PallasIPA::commit(&pcs_ck, &agg_lin).unwrap());

        let coord_sets: Vec<BTreeSet<ark_pallas::Fr>> = coord_vecs
            .iter()
            .cloned()
            .map(BTreeSet::from_iter)
            .collect();
        let vals: Vec<_> = polys
            .iter()
            .zip(coord_vecs.iter())
            .map(|(f, xs)| xs.iter().map(|x| f.evaluate(&x)).collect::<Vec<_>>())
            .collect();

        let transcript = &mut Coeffs(ark_pallas::Fr::rand(rng), ark_pallas::Fr::rand(rng));
        let t_open = start_timer!(|| format!(
            "Opening IPA ring-proof with shplonk, {} polys, max_degree = {}",
            polys.len(),
            polys[7].degree()
        ));
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

    fn _bench_msm<C: CurveGroup>(log_n: u32) {
        let rng = &mut test_rng();
        let n = 2usize.pow(log_n);
        let (scalars, bases): (Vec<_>, Vec<_>) = (0..n)
            .map(|_| (C::ScalarField::rand(rng), C::Affine::rand(rng)))
            .unzip();
        let t_msm = start_timer!(|| format!(
            "log(n)={log_n}, MSM on {}",
            ark_std::any::type_name::<C::Config>()
        ));
        let _res = C::msm(&bases, &scalars);
        end_timer!(t_msm);
    }

    // cargo test bench_msms --release --features="print-trace" -- --show-output
    // qcargo test bench_msms --release --features="parallel print-trace" -- --show-output
    #[test]
    fn bench_msms() {
        let log_n = 9;

        _bench_msm::<ark_pallas::Projective>(log_n);
        _bench_msm::<ark_pallas::Projective>(log_n + 1);
        // _bench_msm::<ark_vesta::Projective>(log_n);
        // _bench_msm::<ark_bls12_381::G1Projective>(log_n);
        // _bench_folding::<ark_pallas::Affine>(log_n);
        // _bench_folding::<ark_pallas::Affine>(log_n + 1);
        _bench_folding(log_n);
        _bench_folding(log_n + 1);

        let rng = &mut test_rng();
        let n = 2usize.pow(log_n);

        let n3 = 3 * n;
        let pcs_params = PallasIPA::setup(n3, rng);

        let p = Poly::<ark_pallas::Fr>::rand(n, rng);
        let t_ipa_commit = start_timer!(|| format!("IPA commitment to a degree {n} polynomial"));
        let _c = PallasIPA::commit(&pcs_params.ck(), &p);
        end_timer!(t_ipa_commit);

        let p = Poly::<ark_pallas::Fr>::rand(n3, rng);
        let t_ipa_commit = start_timer!(|| format!("IPA commitment to a degree 3*{n} polynomial"));
        let _c = PallasIPA::commit(&pcs_params.ck(), &p);
        end_timer!(t_ipa_commit);
    }

    fn mul_endo_wnaf(
        p: ark_pallas::Projective,
        k1: (bool, ark_pallas::Fr),
        k2: (bool, ark_pallas::Fr),
    ) -> ark_pallas::Projective {
        let mut p1 = p;
        let mut p2 = PallasConfig::endomorphism(&p);
        if !k1.0 {
            p1 = -p1;
        }
        if !k2.0 {
            p2 = -p2;
        }
        let w_size = 4;
        let wnaf = WnafContext::new(w_size);
        let p1_table = wnaf.table(p1);
        let p2_table = wnaf.table(p2);
        let k1_wnaf = k1.1.into_bigint().find_wnaf(w_size).unwrap();
        let mut k2_wnaf = k2.1.into_bigint().find_wnaf(w_size).unwrap();
        k2_wnaf.resize(k1_wnaf.len(), 0);

        let mut result = ark_pallas::Projective::zero();
        let mut found_non_zero = false;
        for (n1, n2) in k1_wnaf.into_iter().zip(k2_wnaf).rev() {
            if found_non_zero {
                result.double_in_place();
            }

            if n1 != 0 || n2 != 0 {
                found_non_zero = true;
                if n1 > 0 {
                    result += &p1_table[(n1 / 2) as usize];
                }
                if n1 < 0 {
                    result -= &p1_table[((-n1) / 2) as usize];
                }
                if n2 > 0 {
                    result += &p2_table[(n2 / 2) as usize];
                }
                if n2 < 0 {
                    result -= &p2_table[((-n2) / 2) as usize];
                }
            }
        }
        result
    }

    fn _bench_folding(log_n: u32) {
        let rng = &mut test_rng();
        let n = 2usize.pow(log_n);
        let (l, r): (Vec<ark_pallas::Affine>, Vec<ark_pallas::Affine>) = (0..n)
            .map(|_| (ark_pallas::Affine::rand(rng), ark_pallas::Affine::rand(rng)))
            .unzip();
        let x = ark_pallas::Fr::rand(rng);
        let _timer = start_timer!(|| format!("Naive folding, log(n) = {log_n}"));
        let res: Vec<ark_pallas::Projective> = ark_std::cfg_iter!(l)
            .zip(r.clone())
            .map(|(l, r)| r * x + l)
            .collect();
        end_timer!(_timer);

        let _timer = start_timer!(|| format!("Naive folding with endo, log(n) = {log_n}"));
        let res_: Vec<ark_pallas::Projective> = ark_std::cfg_into_iter!(l.clone())
            .zip(ark_std::cfg_into_iter!(r.clone()))
            .map(|(l, r)| l + <PallasConfig as GLVConfig>::glv_mul_affine(r, x))
            .collect();
        end_timer!(_timer);
        assert_eq!(res_, res);

        let _timer =
            start_timer!(|| format!("Naive folding with endo and w-NAF, log(n) = {log_n}"));
        let ((sgn_k1, k1), (sgn_k2, k2)) = PallasConfig::scalar_decomposition(x);
        let res_: Vec<ark_pallas::Projective> = ark_std::cfg_into_iter!(l)
            .zip(ark_std::cfg_iter!(r))
            .map(|(l, r)| l + mul_endo_wnaf(r.into_group(), (sgn_k1, k1), (sgn_k2, k2)))
            .collect();
        end_timer!(_timer);
        assert_eq!(res_, res);
    }

    fn batch_double_affine<C: GLVConfig>(bases: Vec<Affine<C>>) -> Vec<Affine<C>> {
        let mut denoms: Vec<C::BaseField> = ark_std::cfg_iter!(bases).map(|p| p.y + p.y).collect();

        ark_ff::batch_inversion(&mut denoms);

        ark_std::cfg_iter!(bases)
            .zip(denoms)
            .map(|(p, _2y_inv)| {
                let (x, y) = p.xy().unwrap();
                let t =
                    _2y_inv * (x.square() * C::BaseField::from(3) + <C as SWCurveConfig>::COEFF_A); // (3x^2 + a) / 2y
                let x_n = t.square() - x - x;
                let y_n = t * (x - x_n) - y;
                Affine::<C>::new_unchecked(x_n, y_n)
            })
            .collect()
    }

    fn batch_double_affine_in_place<C: GLVConfig>(bases: &mut [Affine<C>]) {
        let three = C::BaseField::from(3);
        let sw_a = <C as SWCurveConfig>::COEFF_A;
        let mut denoms: Vec<C::BaseField> = ark_std::cfg_iter!(bases).map(|p| p.y + p.y).collect();

        ark_ff::batch_inversion(&mut denoms);
        // ark_ff::batch_inversion_and_mul(&mut denoms, &C::BaseField::one());

        cfg_iter_mut!(bases)
            .zip(ark_std::cfg_into_iter!(denoms))
            .for_each(|(p, _2y_inv)| {
                let t = _2y_inv * (p.x.square() * three + sw_a); // (3x^2 + a) / 2y
                let old_x = p.x;
                p.x = t.square() - p.x - p.x;
                p.y = t * (old_x - p.x) - p.y;
            })
    }

    fn batch_add_affine<C: GLVConfig>(
        bases1: Vec<Affine<C>>,
        bases2: Vec<Affine<C>>,
    ) -> Vec<Affine<C>> {
        let mut denoms: Vec<C::BaseField> = ark_std::cfg_iter!(bases1)
            .zip(ark_std::cfg_iter!(bases2))
            .map(|(p1, p2)| p2.x - p1.x)
            .collect();

        ark_ff::batch_inversion(&mut denoms);

        ark_std::cfg_iter!(bases1)
            .zip(ark_std::cfg_iter!(bases2))
            .zip(ark_std::cfg_iter!(denoms))
            .map(|((p1, p2), _x2_m_x1)| {
                let (x1, y1) = p1.xy().unwrap();
                let (x2, y2) = p2.xy().unwrap();
                let t = (y2 - y1) * _x2_m_x1;
                let x_n = t.square() - x1 - x2;
                let y_n = t * (x1 - x_n) - y1;
                Affine::<C>::new_unchecked(x_n, y_n)
            })
            .collect()
    }

    fn batch_mul_by_x_affine<C: GLVConfig>(
        bases: Vec<Affine<C>>,
        x: C::ScalarField,
    ) -> Vec<Affine<C>> {
        let mut res: Vec<Affine<C>> = bases.clone();
        for b in ark_ff::BitIteratorBE::without_leading_zeros(x.into_bigint()).skip(1) {
            batch_double_affine_in_place(&mut res);
            if b {
                res = batch_add_affine(res, bases.clone());
            }
        }
        res
    }

    #[test]
    fn bench_folding() {
        let rng = &mut test_rng();
        let log_n = 10;
        _bench_folding(log_n);

        let n = 2usize.pow(log_n);
        let bases: Vec<_> = (0..n).map(|_| ark_pallas::Affine::rand(rng)).collect();
        let x = ark_pallas::Fr::rand(rng);
        let dbl: Vec<_> = bases
            .iter()
            .map(|p| {
                let mut p = p.into_group();
                p.double_in_place();
                p.into_affine()
            })
            .collect();
        assert_eq!(dbl, batch_double_affine(bases.clone()));

        let bases2: Vec<_> = (0..n).map(|_| ark_pallas::Affine::rand(rng)).collect();
        let bases1 = bases.clone();
        let add: Vec<_> = bases
            .into_iter()
            .zip(bases2.iter())
            .map(|(p1, p2)| p1 + p2)
            .collect();
        assert_eq!(add, batch_add_affine(bases1.clone(), bases2.clone()));

        let _timer = start_timer!(|| format!("Batch affine folding, log(n) = {log_n}"));
        let x_bases2 = batch_mul_by_x_affine(bases2.clone(), x);
        let res = batch_add_affine(bases1.clone(), x_bases2);
        end_timer!(_timer);

        let _timer = start_timer!(|| format!("Naive folding, log(n) = {log_n}"));
        let res_: Vec<ark_pallas::Projective> = ark_std::cfg_into_iter!(bases1)
            .zip(ark_std::cfg_into_iter!(bases2))
            .map(|(l, r)| l + r * x)
            .collect();
        let _to_affine = start_timer!(|| "batch affine conversion");
        let res_ = ark_pallas::Projective::normalize_batch(&res_);
        end_timer!(_to_affine);
        end_timer!(_timer);

        assert_eq!(res_, res);
    }
}
