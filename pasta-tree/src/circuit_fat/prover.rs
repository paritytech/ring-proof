use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::circuit_fat::params::PiopParams;
use crate::circuit_fat::{ProofComms, ProofEvals};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
// use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ff::One;
use ark_ff::{FftField, PrimeField, Zero};
use ark_poly::Evaluations;
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::FieldColumn;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::ProverGadget;
use w3f_plonk_common::gadgets::booleanity::{BitColumn, Booleanity};
use w3f_plonk_common::gadgets::column_sum::ColumnSumPolys;
use w3f_plonk_common::gadgets::ec::AffineColumn;
use w3f_plonk_common::gadgets::ec::CondAdd;
use w3f_plonk_common::gadgets::equal_cells::CellsEqPolys;
use w3f_plonk_common::gadgets::fixed_cells::FixedCells;
use w3f_plonk_common::gadgets::inner_prod_inv::InnerProdInv;
use w3f_plonk_common::piop::ProverPiop;

pub struct PiopProver<G: AffineRepr<BaseField: FftField>> {
    domain: Domain<G::BaseField>,
    // `x` coordinates of all the children of a node. Public input.
    nodes: FieldColumn<G::BaseField>,
    // `H, 2H, 4H,...,2^sH` Fixed column.
    h_powers: AffineColumn<G::BaseField, G>,
    // `node_x = self.x_coords[self.node_idx]` Private input.
    node_idx: BitColumn<G::BaseField>,
    // Bits of the chosen blinding factor. Private input.
    bf_bits: BitColumn<G::BaseField>,
    selected_node: InnerProdInv<G::BaseField>,
    blinded_node: CondAdd<G::BaseField, G>, // blinded_node.acc[0] = (x_i, y_i) = Ci, blinded_node.acc[capacity] = Ci + bf.H = Ci'
    node_idx_bool: Booleanity<G::BaseField>,
    bf_bits_bool: Booleanity<G::BaseField>,
    node_idx_sum: ColumnSumPolys<G::BaseField>,
    node_idx_sum_vals: FixedCells<G::BaseField>,
    seed_eq_node: CellsEqPolys<G::BaseField>,
}

impl<G: AffineRepr<BaseField: PrimeField>> PiopProver<G> {
    pub fn build(params: &PiopParams<G>, level: LevelWitnessWithBlinding<G>) -> Self {
        let domain = params.domain.clone();
        let x_coords = params.x_coords_column(&level.level_witness.x_coords());
        let h_powers = params.h_powers_column();
        let node_idx = params.node_selector(level.level_witness.path_node_idx);
        let bf_bits = params.bf_bits_column(level.bf);
        let selected_node = InnerProdInv::init(x_coords.clone(), node_idx.col.clone(), &domain);

        let node = level.level_witness.path_node();
        debug_assert_eq!(selected_node.acc.evals[0], node.x().unwrap());
        // here we witness yi
        let blinded_node = CondAdd::init(bf_bits.clone(), h_powers.clone(), node, &domain);
        debug_assert_eq!(
            blinded_node.seed_plus_sum(),
            (node + params.h * level.bf).into_affine()
        );
        debug_assert_eq!(blinded_node.acc.xs.evals[0], node.x().unwrap());
        debug_assert_eq!(blinded_node.acc.ys.evals[0], node.y().unwrap());
        let node_idx_bool = Booleanity::init(node_idx.clone());
        let bf_bits_bool = Booleanity::init(bf_bits.clone());
        let node_idx_sum = ColumnSumPolys::init(node_idx.col.clone(), &domain);
        let node_idx_sum_vals = FixedCells::init(
            node_idx_sum.acc.clone(),
            &domain,
            G::BaseField::zero(),
            G::BaseField::one(),
        );
        let seed_eq_node = CellsEqPolys::first_cells(
            selected_node.acc.clone(),
            blinded_node.acc.xs.clone(),
            &domain,
        );

        Self {
            domain,
            nodes: x_coords,
            h_powers,
            node_idx,
            bf_bits,
            selected_node,
            blinded_node,
            node_idx_bool,
            bf_bits_bool,
            node_idx_sum,
            node_idx_sum_vals,
            seed_eq_node,
        }
    }

    fn _committed_columns<
        C: CurveGroup,
        Fun: Fn(&DensePolynomial<G::BaseField>) -> WrappedAffine<C>,
    >(
        &self,
        commit: Fun,
    ) -> ProofComms<C> {
        let node_idx = commit(self.node_idx.as_poly());
        let bf_bits = commit(self.bf_bits.as_poly());
        let selected_node_acc = commit(self.selected_node.acc.as_poly());
        let blinded_node_acc = [
            commit(self.blinded_node.acc.xs.as_poly()),
            commit(self.blinded_node.acc.ys.as_poly()),
        ];
        let node_idx_sum_acc = commit(self.node_idx_sum.acc.as_poly());
        ProofComms {
            node_idx,
            bf_bits,
            selected_node_acc,
            blinded_node_acc,
            node_idx_sum_acc,
        }
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn _columns(&self) -> Vec<DensePolynomial<G::BaseField>> {
        vec![
            self.nodes.as_poly().clone(),
            self.h_powers.xs.as_poly().clone(),
            self.h_powers.ys.as_poly().clone(),
            self.node_idx.as_poly().clone(),
            self.bf_bits.as_poly().clone(),
            self.selected_node.acc.as_poly().clone(),
            self.blinded_node.acc.xs.as_poly().clone(),
            self.blinded_node.acc.ys.as_poly().clone(),
            self.node_idx_sum.acc.as_poly().clone(),
        ]
    }

    fn _columns_evaluated(&self, zeta: &G::BaseField) -> ProofEvals<G::BaseField> {
        let x_coords = self.nodes.evaluate(zeta);
        let h_powers = [
            self.h_powers.xs.evaluate(zeta),
            self.h_powers.ys.evaluate(zeta),
        ];
        let node_idx = self.node_idx.evaluate(zeta);
        let bf_bits = self.bf_bits.evaluate(zeta);
        let blinded_node_acc = [
            self.blinded_node.acc.xs.evaluate(zeta),
            self.blinded_node.acc.ys.evaluate(zeta),
        ];
        let selected_node_acc = self.selected_node.acc.evaluate(zeta);
        let node_idx_sum_acc = self.node_idx_sum.acc.evaluate(zeta);
        ProofEvals {
            x_coords,
            h_powers,
            node_idx,
            bf_bits,
            selected_node_acc,
            blinded_node_acc,
            node_idx_sum_acc,
        }
    }
}

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>>
    ProverPiop<C::ScalarField, WrappedAffine<C>> for PiopProver<G>
{
    const N_COLUMNS: usize = 9;
    const N_CONSTRAINTS: usize = 12;
    type Commitments = ProofComms<C>;
    type Evaluations = ProofEvals<C::ScalarField>;
    type Instance = G;

    fn quotient(&self, alphas: &[C::ScalarField]) -> Option<Vec<DensePolynomial<C::ScalarField>>> {
        let chunks =
            <Self as ProverPiop<C::ScalarField, WrappedAffine<C>>>::_quotient_chunks(self, alphas);
        debug_assert_eq!(chunks.as_ref().unwrap().len(), 4);
        debug_assert_eq!(chunks.as_ref().unwrap()[3].degree(), 0);
        chunks
    }

    fn committed_columns<Fun: Fn(&DensePolynomial<C::ScalarField>) -> WrappedAffine<C>>(
        &self,
        commit: Fun,
    ) -> Self::Commitments {
        self._committed_columns(commit)
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn columns(&self) -> Vec<DensePolynomial<C::ScalarField>> {
        self._columns()
    }

    fn columns_evaluated(&self, zeta: &C::ScalarField) -> Self::Evaluations {
        self._columns_evaluated(zeta)
    }

    fn constraints(&self) -> Vec<Evaluations<C::ScalarField>> {
        let (node_blinded_x, node_blinded_y) = self.blinded_node.seed_plus_sum().xy().unwrap();
        vec![
            self.selected_node.constraints(),
            self.blinded_node.constraints(),
            self.node_idx_sum.constraints(),
            self.node_idx_bool.constraints(),
            self.bf_bits_bool.constraints(),
            self.node_idx_sum_vals.constraints(),
            vec![FixedCells::constraint_cell(
                &self.blinded_node.acc.xs,
                &self.domain.l_last,
                self.domain.capacity - 1,
                node_blinded_x,
            )],
            vec![FixedCells::constraint_cell(
                &self.blinded_node.acc.ys,
                &self.domain.l_last,
                self.domain.capacity - 1,
                node_blinded_y,
            )],
            vec![FixedCells::constraint_cell(
                &self.selected_node.acc,
                &self.domain.l_last,
                self.domain.capacity - 1,
                C::ScalarField::zero(),
            )],
            self.seed_eq_node.constraints(),
            // vec![self.blinded_node.acc.on_curve_constraint()],
            // this prevents opening to -parent=(x,-y)
            // parent = commit([x1, ..., xl, 1, 0, 0, 0]; 0) = x1.G1 + ... + xl.Gl + 1.G_{l+1}
            // then -parent = commit([-x1, ..., -xl, -1, 0, 0, 0]; 0)
            vec![FixedCells::constraint_cell(
                &self.nodes,
                &self.domain.l_last,
                self.domain.capacity - 1,
                C::ScalarField::one(),
            )],
        ]
        .concat()
    }

    fn constraints_lin(&self, zeta: &C::ScalarField) -> Vec<DensePolynomial<C::ScalarField>> {
        vec![
            self.selected_node.constraints_linearized(zeta),
            self.blinded_node.constraints_linearized(zeta),
            self.node_idx_sum.constraints_linearized(zeta),
            self.node_idx_bool.constraints_linearized(zeta),
            self.bf_bits_bool.constraints_linearized(zeta),
            self.node_idx_sum_vals.constraints_linearized(zeta),
            vec![DensePolynomial::zero()],
            vec![DensePolynomial::zero()],
            vec![DensePolynomial::zero()],
            self.seed_eq_node.constraints_linearized(zeta),
            // vec![DensePolynomial::zero()],
            vec![DensePolynomial::zero()],
        ]
        .concat()
    }

    fn domain(&self) -> &Domain<C::ScalarField> {
        &self.domain
    }

    fn result(&self) -> Self::Instance {
        self.blinded_node.seed_plus_sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::random_witness;
    use ark_bls12_381::G1Projective;
    use ark_ed_on_bls12_381_bandersnatch::{Fq, Fr, SWAffine};
    use ark_std::{UniformRand, test_rng};
    use w3f_pcs::pcs::commitment::WrappedAffine;

    #[test]
    fn test_constraints() {
        let rng = &mut test_rng();

        let domain_size = 256;
        let domain = Domain::<Fq>::with_zk_rows(domain_size, 3);

        let node = SWAffine::rand(rng);
        let h = SWAffine::rand(rng);
        let bf = Fr::from(u128::rand(rng));
        let blinded_node = (node + h * bf).into_affine();

        let piop_params = PiopParams::setup(domain, h);
        let witness =
            random_witness(piop_params.max_nodes(), node, rng).with_blinding(bf, Fq::zero());
        let piop = PiopProver::build(&piop_params, witness);

        assert!(ProverPiop::<_, WrappedAffine<G1Projective>>::constraints_satisfied(&piop));
        assert_eq!(
            ProverPiop::<_, WrappedAffine<G1Projective>>::result(&piop),
            blinded_node
        );
    }
}
