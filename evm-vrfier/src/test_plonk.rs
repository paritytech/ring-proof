alloy::sol!(
    #[sol(rpc)]
    Plonk,
    "contracts/out/Plonk.sol/Plonk.json"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_g1, encode_g2, fr_to_uint, G1Point, G2Point};
    use alloy::primitives::U256;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ec::twisted_edwards::{Affine, TECurveConfig};
    use ark_ec::PrimeGroup;
    use ark_ed_on_bls12_381_bandersnatch::EdwardsConfig;
    use ark_ff::{BigInteger, One, PrimeField};
    use ark_std::rand::Rng;
    use ark_std::{test_rng, UniformRand};
    use w3f_pcs::aggregation::single::aggregate_polys;
    use w3f_pcs::pcs::kzg::params::RawKzgVerifierKey;
    use w3f_pcs::pcs::kzg::urs::URS;
    use w3f_pcs::pcs::kzg::KZG;
    use w3f_pcs::pcs::{PcsParams, PCS};

    use w3f_pcs::Polynomial;
    use w3f_plonk_common::domain::Domain;
    use w3f_plonk_common::gadgets::booleanity::BitColumn;
    use w3f_plonk_common::gadgets::ec::te_doubling::Doubling;
    use w3f_plonk_common::gadgets::ec::{AffineColumn, CondAdd};
    use w3f_plonk_common::gadgets::ProverGadget;
    use w3f_plonk_common::prover::aggregate_evaluations;
    use w3f_plonk_common::Column;

    impl From<G1Point> for BLS::G1Point {
        fn from(p: G1Point) -> Self {
            Self {
                x_a: p.x_a,
                x_b: p.x_b,
                y_a: p.y_a,
                y_b: p.y_b,
            }
        }
    }

    impl From<G2Point> for BLS::G2Point {
        fn from(p: G2Point) -> Self {
            Self {
                x_c0_a: p.x_c0_a,
                x_c0_b: p.x_c0_b,
                x_c1_a: p.x_c1_a,
                x_c1_b: p.x_c1_b,
                y_c0_a: p.y_c0_a,
                y_c0_b: p.y_c0_b,
                y_c1_a: p.y_c1_a,
                y_c1_b: p.y_c1_b,
            }
        }
    }

    struct ArkProof<E: Pairing> {
        columns: Vec<E::G1Affine>,
        quotient: E::G1Affine,
        z: E::ScalarField,
        columns_at_z: Vec<E::ScalarField>,
        columns_at_zw: Vec<E::ScalarField>,
        kzg_proof_at_z: E::G1Affine,
        kzg_proof_at_zw: E::G1Affine,
    }

    struct EthProof {
        columns: Vec<BLS::G1Point>,
        quotient: BLS::G1Point,
        z: U256,
        columns_at_z: Vec<U256>,
        columns_at_zw: Vec<U256>,
        kzg_proof_at_z: BLS::G1Point,
        kzg_proof_at_zw: BLS::G1Point,
    }

    impl ArkProof<Bls12_381> {
        fn encode(self) -> EthProof {
            EthProof {
                columns: self
                    .columns
                    .into_iter()
                    .map(|p| encode_g1(p).into())
                    .collect(),
                quotient: encode_g1(self.quotient).into(),
                z: fr_to_uint(self.z),
                columns_at_z: self.columns_at_z.into_iter().map(fr_to_uint).collect(),
                columns_at_zw: self.columns_at_zw.into_iter().map(fr_to_uint).collect(),
                kzg_proof_at_z: encode_g1(self.kzg_proof_at_z).into(),
                kzg_proof_at_zw: encode_g1(self.kzg_proof_at_zw).into(),
            }
        }
    }

    fn produce_proof<E: Pairing, Jubjub: TECurveConfig<BaseField = E::ScalarField>, R: Rng>(
        rng: &mut R,
    ) -> (ArkProof<E>, RawKzgVerifierKey<E>, Vec<E::ScalarField>) {
        let n = 256;
        let domain = Domain::new(n, true);

        // KZG setup
        let urs = URS::from_trapdoor(
            E::ScalarField::rand(rng),
            3 * n + 1,
            2,
            E::G1::generator(),
            E::G2::generator(),
        );
        let (ck, rvk) = (urs.ck(), urs.raw_vk());

        // scalar.POINT
        let scalar = Jubjub::ScalarField::rand(rng);
        let scalar_bits = &scalar.into_bigint().to_bits_le()[..252];
        let scalar_bits = BitColumn::init(scalar_bits.to_vec(), &domain);
        let point = Affine::<Jubjub>::rand(rng);
        let doublings = Doubling::doublings_of(point, &domain);
        let doublings = AffineColumn::public_column(doublings, &domain);
        let seed = Affine::<Jubjub>::rand(rng);
        let cond_add = CondAdd::init(scalar_bits.clone(), doublings.clone(), seed, &domain);

        let column_polys = vec![
            cond_add.acc.xs.as_poly().clone(),
            cond_add.acc.ys.as_poly().clone(),
            doublings.xs.as_poly().clone(),
            doublings.ys.as_poly().clone(),
            scalar_bits.as_poly().clone(),
        ];

        let column_commitments: Vec<E::G1Affine> = column_polys
            .iter()
            .map(|p| KZG::<E>::commit(&ck, p).unwrap().0)
            .collect();

        // TODO: sample alphas (coeffs to agg constraints)
        let constraints = cond_add.constraints();
        let agg_constraint = aggregate_evaluations(
            &constraints,
            &[E::ScalarField::one(), E::ScalarField::one()],
        );
        let quotient_poly = domain.divide_by_vanishing_poly(&agg_constraint.interpolate());
        let quotient_commitment = KZG::<E>::commit(&ck, &quotient_poly).unwrap().0;

        // sample zeta
        let z = E::ScalarField::rand(rng);
        let zw = z * domain.omega();
        let columns_at_z = column_polys.iter().map(|p| p.evaluate(&z)).collect();
        let columns_at_zw = column_polys[..2].iter().map(|p| p.evaluate(&zw)).collect();

        // sample nus
        let mut polys_at_z = column_polys.clone();
        polys_at_z.push(quotient_poly);
        let nus: Vec<E::ScalarField> = (0..polys_at_z.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        let agg_poly_z = aggregate_polys(&polys_at_z, &nus);
        let agg_columns_zw = aggregate_polys(&column_polys[..2], &nus[..2]);

        let kzg_proof_at_z = KZG::<E>::open(&ck, &agg_poly_z, z).unwrap();
        let kzg_proof_at_zw = KZG::<E>::open(&ck, &agg_columns_zw, zw).unwrap();

        let proof = ArkProof {
            columns: column_commitments,
            quotient: quotient_commitment,
            z,
            columns_at_z,
            columns_at_zw,
            kzg_proof_at_z,
            kzg_proof_at_zw,
        };

        (proof, rvk, nus)
    }

    #[tokio::test]
    async fn verify_proof() -> Result<(), Box<dyn std::error::Error>> {
        let provider = alloy::providers::builder()
            .with_recommended_fillers()
            .on_anvil_with_wallet_and_config(|anvil| anvil.prague())?;

        let (test_proof, kzg_vk, nus) =
            produce_proof::<Bls12_381, EdwardsConfig, _>(&mut test_rng());
        let test_proof = test_proof.encode();

        let plonk = Plonk::deploy(&provider, encode_g2(kzg_vk.tau_in_g2).into()).await?;

        let res = plonk
            .verify_proof(
                test_proof.columns,
                test_proof.quotient,
                test_proof.z,
                test_proof.columns_at_z,
                test_proof.columns_at_zw,
                test_proof.kzg_proof_at_z,
                test_proof.kzg_proof_at_zw,
                nus.into_iter().map(fr_to_uint).collect(),
            )
            .call()
            .await?;
        assert!(res);

        Ok(())
    }
}
