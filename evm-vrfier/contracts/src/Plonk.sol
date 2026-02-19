pragma solidity ^0.8.24;

import {BLS, Kzg} from "src/Kzg.sol";
import {Constraints} from "src/Constraints.sol";

contract Plonk {
    // The trapdoor `tau` in G2, part of the standard KZG verification key.
    BLS.G2Point tau_g2;

    constructor(BLS.G2Point memory tau_g2_) {
        tau_g2 = tau_g2_;
    }

    function verify_proof(
        BLS.G1Point[] memory columns,
        BLS.G1Point memory quotient,
        uint256 z,
        uint256[] memory columns_at_z,
        uint256[] memory columns_at_zw,
        BLS.G1Point memory kzg_proof_at_z,
        BLS.G1Point memory kzg_proof_at_zw,
        uint256[] memory nus
    ) public view returns (bool) {
        uint256 k = columns.length;
        require(columns_at_z.length == k);
        require(columns_at_zw.length <= k);

        BLS.G1Point[] memory polys = new BLS.G1Point[](k + 1);
        for (uint256 i = 0; i < k; i++) {
            polys[i] = columns[i];
        }
        polys[k] = quotient;

        uint256[] memory evals_at_z = new uint256[](k + 1);
        for (uint256 i = 0; i < k; i++) {
            evals_at_z[i] = columns_at_z[i];
        }
        evals_at_z[k] = compute_quotient(columns_at_z, columns_at_zw, z);

        BLS.G1Point[] memory kzg_proofs = new BLS.G1Point[](2);
        kzg_proofs[0] = kzg_proof_at_z;
        kzg_proofs[1] = kzg_proof_at_zw;
        uint256[] memory zs = new uint256[](2);
        zs[0] = z;
        zs[1] = Constraints.mul(z, Constraints.w);
        return Kzg.verify_plonk_kzg(polys, zs, evals_at_z, columns_at_zw, kzg_proofs, nus, tau_g2);
    }

    function compute_quotient(uint256[] memory columns_at_z1, uint256[] memory columns_at_z2, uint256 z)
        internal
        view
        returns (uint256)
    {
        uint256 not_last = Constraints.not_last_row(z);
        (uint256 cx, uint256 cy) = Constraints.cond_te_addition(
            columns_at_z1[4],
            columns_at_z1[0],
            columns_at_z1[1],
            columns_at_z1[2],
            columns_at_z1[3],
            columns_at_z2[0],
            columns_at_z2[1],
            not_last
        );
        return Constraints.quotient_at(Constraints.add(cx, cy), z); //TODO: alphas
    }
}
