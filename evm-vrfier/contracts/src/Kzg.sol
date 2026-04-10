pragma solidity ^0.8.24;

import "./BlsGenerators.sol";

library Kzg {
    // Verifies a batch of `2` kzg proofs:
    // 1. `proofs[0]` certifying that `polys[i](zs[0]) = evals_at_z1[i], i = 0,...,k, k = evals_at_z1.length`,
    // 2. `proofs[1]` certifying that `polys[j](zs[1]) = evals_at_z2[j], j = 0,...,l, l = evals_at_z2.length`.
    function verify_plonk_kzg(
        BLS.G1Point[] memory polys,
        uint256[] memory zs,
        uint256[] memory evals_at_z1,
        uint256[] memory evals_at_z2,
        BLS.G1Point[] memory proofs,
        uint256[] memory nus,
        //        uint256 r,
        BLS.G2Point memory tau_g2
    ) internal view returns (bool) {
        uint256 r = 123; //TODO

        uint256 k = polys.length;
        assert(evals_at_z1.length == k);
        assert(nus.length == k);
        uint256 l = evals_at_z2.length;
        assert(l <= k);

        // all the g1 points the verifier knows should go to a single msm
        uint256 n_bases = k + 3; // `n` commitments to the polynomials, proofs in `zs[0]` and `zs[1]`, and `g1` to commit to the evaluations

        BLS.G1Point[] memory msm_bases = new BLS.G1Point[](n_bases);
        bytes32[] memory msm_scalars = new bytes32[](n_bases);

        uint256 i;
        for (i = 0; i < k; i++) {
            msm_bases[i] = polys[i];
        }

        uint256 r_plus_1 = BlsGenerators.add_fr(r, 1);
        for (i = 0; i < l; i++) {
            msm_scalars[i] = bytes32(BlsGenerators.mul_fr(r_plus_1, nus[i]));
        }
        for (i = l; i < k; i++) {
            msm_scalars[i] = bytes32(nus[i]);
        }

        uint256 agg_at_z = 0;
        for (i = 0; i < l; i++) {
            agg_at_z = BlsGenerators.add_fr(agg_at_z, BlsGenerators.mul_fr(uint256(nus[i]), evals_at_z2[i]));
        }
        agg_at_z = BlsGenerators.mul_fr(agg_at_z, r);
        for (i = 0; i < polys.length; i++) {
            agg_at_z = BlsGenerators.add_fr(agg_at_z, BlsGenerators.mul_fr(uint256(nus[i]), evals_at_z1[i]));
        }
        msm_bases[i] = BlsGenerators.G1();
        msm_scalars[i] = bytes32(BlsGenerators.q - agg_at_z);

        msm_bases[++i] = proofs[0];
        msm_scalars[i] = bytes32(zs[0]);

        msm_bases[++i] = proofs[1];
        msm_scalars[i] = bytes32(BlsGenerators.mul_fr(r, zs[1]));

        BLS.G1Point memory agg_acc = BLS.msm(msm_bases, msm_scalars);
        BLS.G1Point memory acc_proof = BLS.add(proofs[0], BlsGenerators.g1_mul(proofs[1], bytes32(r)));
        return verify_acc(agg_acc, acc_proof, tau_g2);
    }

    function verify(BLS.G1Point memory c, uint256 z, uint256 v, BLS.G1Point memory proof, BLS.G2Point memory tau_g2)
        internal
        view
        returns (bool)
    {
        bytes32[] memory msm_scalars = new bytes32[](2);
        BLS.G1Point[] memory msm_bases = new BLS.G1Point[](2);
        msm_scalars[0] = bytes32(z);
        msm_bases[0] = proof;
        msm_scalars[1] = bytes32(BlsGenerators.q - v);
        msm_bases[1] = BlsGenerators.G1();
        BLS.G1Point memory acc = BLS.msm(msm_bases, msm_scalars);
        acc = BLS.add(acc, c);
        return verify_acc(acc, proof, tau_g2);
    }

    function verify_acc(BLS.G1Point memory acc, BLS.G1Point memory acc_proof, BLS.G2Point memory tau_g2)
        internal
        view
        returns (bool)
    {
        return pairing2(acc, BlsGenerators.G2_NEG(), acc_proof, tau_g2);
    }

    function pairing2(
        BLS.G1Point memory g1_1,
        BLS.G2Point memory g2_1,
        BLS.G1Point memory g1_2,
        BLS.G2Point memory g2_2
    ) internal view returns (bool result) {
        BLS.G1Point[] memory g1_points = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2_points = new BLS.G2Point[](2);
        g1_points[0] = g1_1;
        g2_points[0] = g2_1;
        g1_points[1] = g1_2;
        g2_points[1] = g2_2;
        return BLS.pairing(g1_points, g2_points);
    }
}
