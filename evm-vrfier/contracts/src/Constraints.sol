pragma solidity ^0.8.24;

library Constraints {
    uint256 constant domain_size = 256;

    uint256 constant w = 36007022166693598376559747923784822035233416720563672082740011604939309541707;
    uint256 constant w_inv = 11184958699465346337974417366548385058372410568086779736245770566382283753344;
    uint256 constant w_inv_2 = 43775291915288810309377910988321681322896939416379112495208008906206324170002;
    uint256 constant w_inv_3 = 24824062393296269928157607240610716359041681219294130923310247842219009400878;
    uint256 constant w_inv_4 = 45254319123522011116259460062854627366454101350769349111320208945036885998124;

    uint256 constant r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 constant te_coeff_a = r - 5;

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = addmod(a, b, r);
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = mulmod(a, b, r);
    }

    function cond_te_addition(
        uint256 b,
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2,
        uint256 x3,
        uint256 y3,
        uint256 not_last
    ) internal pure returns (uint256 cx, uint256 cy) {
        /// `cx = {[(a.x1.x2 + y1.y2).x3 - x1.y1 - x2.y2].b + (x3 - x1).(1 - b)}.not_last`
        /// `cy = {[(x1.y2 - x2.y1).y3 - x1.y1 + x2.y2].b + (y3 - y1).(1 - b)}.not_last`
        uint256 x1y1 = mul(x1, y1);
        uint256 x2y2 = mul(x2, y2);
        uint256 one_minus_b = add(1, r - b);
        // forgefmt: disable-next-item
        cx = mul( // [(a.x1.x2 + y1.y2).x3 - x1.y1 - x2.y2].b
            add(
                mul(
                    add(mul(te_coeff_a, mul(x1, x2)), mul(y1, y2)), //a.x1.x2 + y1.y2
                    x3
                ),
                r - add(x1y1, x2y2)
            ),
            b
        );
        cx = mul(add(cx, mul(add(x3, r - x1), one_minus_b)), not_last);
        // forgefmt: disable-next-item
        cy = mul( // [(x1.y2 - x2.y1).y3 - x1.y1 + x2.y2].b
            add(
                add(
                    mul(

                        add(mul(x1, y2), r - mul(x2,y1)), //x1.y2 - x2.y1
                        y3
                    ),
                    r - x1y1),
                x2y2
            ),
            b
        );
        cy = mul(add(cy, mul(add(y3, r - y1), one_minus_b)), not_last);
    }

    function mod_exp(uint256 base, uint256 exp) internal view returns (uint256) {
        bytes memory precompileData = abi.encode(32, 32, 32, base, exp, r);
        (bool ok, bytes memory data) = address(5).staticcall(precompileData);
        require(ok, "expMod failed");
        return abi.decode(data, (uint256));
    }

    function inv(uint256 x) internal view returns (uint256) {
        return mod_exp(x, r - 2);
    }

    function v_at(uint256 z) internal view returns (uint256) {
        return mod_exp(z, domain_size) - 1;
    }

    function v_inv_at(uint256 z) internal view returns (uint256) {
        return inv(v_at(z));
    }

    function v_inv_hiding_at(uint256 z) internal view returns (uint256) {
        return mul(mul(mul(v_inv_at(z), add(z, r - w_inv)), add(z, r - w_inv_2)), add(z, r - w_inv_3));
    }

    function quotient_at(uint256 c, uint256 z) internal view returns (uint256) {
        return mul(c, v_inv_hiding_at(z));
    }

    function not_last_row(uint256 z) internal pure returns (uint256) {
        return add(z, r - w_inv_4);
    }
}
