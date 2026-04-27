pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Constraints} from "src/Constraints.sol";

library ConstraintsExt {
    function cond_te_addition(
        uint256 b,
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2,
        uint256 x3,
        uint256 y3,
        uint256 not_last
    ) public pure returns (uint256, uint256) {
        return Constraints.cond_te_addition(b, x1, y1, x2, y2, x3, y3, not_last);
    }

    function mod_exp(uint256 base, uint256 exp) public view returns (uint256) {
        return Constraints.mod_exp(base, exp);
    }

    function inv(uint256 x) public view returns (uint256) {
        return Constraints.inv(x);
    }

    function v_at(uint256 z) public view returns (uint256) {
        return Constraints.v_at(z);
    }

    function v_inv_at(uint256 z) public view returns (uint256) {
        return Constraints.v_inv_at(z);
    }

    function v_inv_hiding_at(uint256 z) public view returns (uint256) {
        return Constraints.v_inv_hiding_at(z);
    }

    function quotient_at(uint256 c, uint256 z) public view returns (uint256) {
        return Constraints.quotient_at(c, z);
    }

    function not_last_row(uint256 z) public pure returns (uint256) {
        return Constraints.not_last_row(z);
    }
}
