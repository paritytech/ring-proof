use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use w3f_plonk_common::domain::Domain;
use w3f_ring_proof::pcs::PCS;
use w3f_ring_proof::PiopParams;

fn setup<R: Rng, F: PrimeField, CS: PCS<F>, JubJub: AffineRepr<BaseField = F>>(
    rng: &mut R,
    domain_size: usize,
) -> (CS::Params, PiopParams<F, JubJub>) {
    let setup_degree = 3 * domain_size;
    let pcs_params = CS::setup(setup_degree, rng);
    let domain = Domain::new(domain_size, true);
    let h = JubJub::rand(rng);
    let seed = JubJub::rand(rng);
    let padding = JubJub::rand(rng);
    let piop_params = PiopParams::setup(domain, h, seed, padding);

    (pcs_params, piop_params)
}

#[cfg(test)]
mod tests {
    use ark_std::test_rng;
    use w3f_plonk_common::test_helpers::random_vec;
    use w3f_pcs::pcs::ipa::IPA;

    #[test]
    fn it_works() {
        let rng = &mut test_rng();

        let log_n = 9;
        let domain_size = 2usize.pow(log_n);

        let (pcs_params, piop_params) = crate::setup::<_, ark_pallas::Fr, IPA<ark_pallas::Projective>, ark_vesta::Affine>(rng, domain_size);
        let keyset_size = piop_params.keyset_part_size;
        let pks = random_vec::<ark_vesta::Affine, _>(keyset_size, rng);
        let (prover_key, verifier_key) = w3f_ring_proof::index::<_, IPA<ark_pallas::Projective>, _>(&pcs_params, &piop_params, &pks);
    }
}
