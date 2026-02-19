#[cfg(test)]
mod tests {
    use crate::{fr_to_uint, unit_to_fr};
    use alloy::primitives::U256;
    use ark_bls12_381::Fr;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig;
    use ark_ff::{Field, One};
    use ark_std::{test_rng, UniformRand};
    use w3f_plonk_common::domain::Domain;
    use w3f_plonk_common::gadgets::ec::te_cond_add::cond_te_addition;

    alloy::sol!(
        #[sol(rpc)]
        Constraints,
        "contracts/out/Constraints.t.sol/ConstraintsExt.json"
    );

    #[tokio::test]
    async fn constraints() -> Result<(), Box<dyn std::error::Error>> {
        let provider = alloy::providers::builder()
            .with_recommended_fillers()
            .on_anvil_with_wallet();
        let constraints = Constraints::deploy(&provider).await?;

        let rng = &mut test_rng();

        let te_coeff_a = BandersnatchConfig::COEFF_A;
        let b = Fr::rand(rng);
        let x1 = Fr::rand(rng);
        let y1 = Fr::rand(rng);
        let x2 = Fr::rand(rng);
        let y2 = Fr::rand(rng);
        let x3 = Fr::rand(rng);
        let y3 = Fr::rand(rng);
        let not_last = Fr::rand(rng);
        let cs_rust = cond_te_addition(
            te_coeff_a,
            &b,
            &x1,
            &y1,
            &x2,
            &y2,
            x3,
            y3,
            &not_last,
            Fr::one(),
        );
        let cs_sol = constraints
            .cond_te_addition(
                fr_to_uint(b),
                fr_to_uint(x1),
                fr_to_uint(y1),
                fr_to_uint(x2),
                fr_to_uint(y2),
                fr_to_uint(x3),
                fr_to_uint(y3),
                fr_to_uint(not_last),
            )
            .call()
            .await?;
        assert_eq!(unit_to_fr(cs_sol._0), cs_rust[0]);
        assert_eq!(unit_to_fr(cs_sol._1), cs_rust[1]);

        Ok(())
    }

    #[tokio::test]
    async fn domain_at_zeta() -> Result<(), Box<dyn std::error::Error>> {
        let provider = alloy::providers::builder()
            .with_recommended_fillers()
            .on_anvil_with_wallet();

        let constraints = Constraints::deploy(&provider).await?;

        let rng = &mut test_rng();

        let domain = Domain::new(256, true);

        let w = domain.omega();
        let w_inv = domain.omega_inv();
        let w_inv_2 = w_inv * w_inv;
        let w_inv_3 = w_inv_2 * w_inv;
        let w_inv_4 = w_inv_3 * w_inv;
        println!("\tuint256 constant w = {};", fr_to_uint(w));
        println!("\tuint256 constant w_inv = {};", fr_to_uint(w_inv));
        println!("\tuint256 constant w_inv_2 = {};", fr_to_uint(w_inv_2));
        println!("\tuint256 constant w_inv_3 = {};", fr_to_uint(w_inv_3));
        println!("\tuint256 constant w_inv_4 = {};", fr_to_uint(w_inv_4));

        let z = Fr::rand(rng);
        let domain_at_z = domain.evaluate(z);

        let z_n = constraints
            .mod_exp(fr_to_uint(z), U256::from(123))
            .call()
            .await?;
        assert_eq!(unit_to_fr(z_n), z.pow([123]));

        let z_inv = constraints.inv(fr_to_uint(z)).call().await?;
        assert_eq!(unit_to_fr(z_inv), z.inverse().unwrap());

        let v_inv_hiding_at = constraints.v_inv_hiding_at(fr_to_uint(z)).call().await?;
        assert_eq!(
            unit_to_fr(v_inv_hiding_at),
            domain_at_z.vanishing_polynomial_inv
        );

        let not_last_row = constraints.not_last_row(fr_to_uint(z)).call().await?;
        assert_eq!(unit_to_fr(not_last_row), domain_at_z.not_last_row);

        Ok(())
    }
}
