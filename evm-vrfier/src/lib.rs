use alloy::primitives::{FixedBytes, U256};
use ark_ff::{BigInteger, PrimeField};

mod test_constraints;
mod test_kzg;
mod test_plonk;

alloy::sol! {
    struct G1Point {
        bytes32 x_a;
        bytes32 x_b;
        bytes32 y_a;
        bytes32 y_b;
    }

    struct G2Point {
        bytes32 x_c0_a;
        bytes32 x_c0_b;
        bytes32 x_c1_a;
        bytes32 x_c1_b;
        bytes32 y_c0_a;
        bytes32 y_c0_b;
        bytes32 y_c1_a;
        bytes32 y_c1_b;
    }
}

/// Encodes a BLS12-381 base field element (381 bits) into 2 bytes32 as specified in
/// [eip-2537](https://eips.ethereum.org/EIPS/eip-2537#fine-points-and-encoding-of-base-elements):
/// > A base field element (Fp) is encoded as 64 bytes
/// > by performing the BigEndian encoding of the corresponding (unsigned) integer.
/// > Due to the size of p, the top 16 bytes are always zeroes.
pub fn fq_to_bytes(fq: ark_bls12_381::Fq) -> [FixedBytes<32>; 2] {
    let be_bytes = fq.into_bigint().to_bytes_be(); // 48 bytes
    let high_bytes = FixedBytes::left_padding_from(&be_bytes[..16]); // 16 bytes
    let low_bytes = FixedBytes::from_slice(&be_bytes[16..]); // 32 bytes
    [high_bytes, low_bytes]
}

pub fn fr_to_bytes(fr: ark_bls12_381::Fr) -> FixedBytes<32> {
    let be_bytes = fr.into_bigint().to_bytes_be();
    FixedBytes::left_padding_from(&be_bytes)
}

pub fn fr_to_uint(fr: ark_bls12_381::Fr) -> U256 {
    let be_bytes = fr.into_bigint().to_bytes_be();
    U256::from_be_slice(&be_bytes)
}

pub fn unit_to_fr(f: U256) -> ark_bls12_381::Fr {
    ark_bls12_381::Fr::from_le_bytes_mod_order(&f.as_le_bytes())
}

pub fn encode_g1(p: ark_bls12_381::G1Affine) -> G1Point {
    let [x_a, x_b] = fq_to_bytes(p.x);
    let [y_a, y_b] = fq_to_bytes(p.y);
    G1Point { x_a, x_b, y_a, y_b }
}

pub fn encode_g2(p: ark_bls12_381::G2Affine) -> G2Point {
    let [x_c0_a, x_c0_b] = fq_to_bytes(p.x.c0);
    let [x_c1_a, x_c1_b] = fq_to_bytes(p.x.c1);
    let [y_c0_a, y_c0_b] = fq_to_bytes(p.y.c0);
    let [y_c1_a, y_c1_b] = fq_to_bytes(p.y.c1);
    G2Point {
        x_c0_a,
        x_c0_b,
        x_c1_a,
        x_c1_b,
        y_c0_a,
        y_c0_b,
        y_c1_a,
        y_c1_b,
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Uint;

    alloy::sol!(
        #[sol(rpc)]
        Counter,
        "contracts/out/Counter.sol/Counter.json"
    );

    #[tokio::test]
    async fn it_works() -> Result<(), Box<dyn std::error::Error>> {
        let provider = alloy::providers::builder()
            .with_recommended_fillers()
            .on_anvil_with_wallet();

        let counter = Counter::deploy(&provider).await?;

        let number = counter.number().call().await?;
        let _ = counter.increment().send().await?;
        assert_eq!(counter.number().call().await?, number + Uint::from(1));

        Ok(())
    }
}
