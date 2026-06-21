use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::circuit_fat::params::PiopParams;
use crate::circuit_fat::{ProofComms, ProofEvals};
use crate::{AffinePoint, CurveModel};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::{FftField, PrimeField, Zero};
use ark_poly::Evaluations;
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
    x_coords: FieldColumn<G::BaseField>,
    // `H, 2H, 4H,...,2^sH` Fixed column.
    h_powers: AffineColumn<G::BaseField, G>,
    // `node_x = self.x_coords[self.node_idx]` Private input.
    node_idx: BitColumn<G::BaseField>,
    // Bits of the chosen blinding factor. Private input.
    bf_bits: BitColumn<G::BaseField>,

    selected_node_acc: FieldColumn<G::BaseField>,
    blinded_node_acc: AffineColumn<G::BaseField, G>,
    node_idx_sum_acc: FieldColumn<G::BaseField>,

    gadgets: Vec<Box<dyn ProverGadget<G::BaseField>>>,
    result: G,
}

impl<G: CurveModel<BaseField: PrimeField>> PiopProver<AffinePoint<G>> {
    pub fn build(
        params: &PiopParams<AffinePoint<G>>,
        level: LevelWitnessWithBlinding<AffinePoint<G>>,
    ) -> Self {
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

        let result = blinded_node.seed_plus_sum();
        let (node_blinded_x, node_blinded_y) = result.xy().unwrap();

        let blinded_node_val_x =
            FixedCells::last(blinded_node.acc.xs.clone(), &domain, node_blinded_x);
        let blinded_node_val_y =
            FixedCells::last(blinded_node.acc.ys.clone(), &domain, node_blinded_y);
        let selected_node_val =
            FixedCells::last(selected_node.acc.clone(), &domain, G::BaseField::zero());
        // this prevents opening to -parent=(x,-y)
        // parent = commit([x1, ..., xl, 1, 0, 0, 0]; 0) = x1.G1 + ... + xl.Gl + 1.G_{l+1}
        // then -parent = commit([-x1, ..., -xl, -1, 0, 0, 0]; 0)
        // TODO:
        let mut x_coords_with_one_cell = x_coords.clone();
        x_coords_with_one_cell.payload_len = domain.capacity;
        let one_cell = FixedCells::last(x_coords_with_one_cell, &domain, G::BaseField::one());

        let selected_node_acc = selected_node.acc.clone();
        let blinded_node_acc = blinded_node.acc.clone();
        let node_idx_sum_acc = node_idx_sum.acc.clone();

        let mut gadgets: Vec<Box<dyn ProverGadget<G::BaseField>>> = Vec::new();
        gadgets.push(Box::new(selected_node));
        gadgets.push(Box::new(blinded_node));
        gadgets.push(Box::new(node_idx_sum));
        gadgets.push(Box::new(node_idx_bool));
        gadgets.push(Box::new(bf_bits_bool));
        gadgets.push(Box::new(node_idx_sum_vals));
        gadgets.push(Box::new(blinded_node_val_x));
        gadgets.push(Box::new(blinded_node_val_y));
        gadgets.push(Box::new(selected_node_val));
        gadgets.push(Box::new(seed_eq_node));
        gadgets.push(Box::new(blinded_node_acc.clone()));
        gadgets.push(Box::new(one_cell));

        Self {
            domain,
            x_coords,
            h_powers,
            node_idx,
            bf_bits,
            selected_node_acc,
            blinded_node_acc,
            node_idx_sum_acc,
            gadgets,
            result,
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
        let selected_node_acc = commit(self.selected_node_acc.as_poly());
        let blinded_node_acc = [
            commit(self.blinded_node_acc.xs.as_poly()),
            commit(self.blinded_node_acc.ys.as_poly()),
        ];
        let node_idx_sum_acc = commit(self.node_idx_sum_acc.as_poly());
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
            self.x_coords.as_poly().clone(),
            self.h_powers.xs.as_poly().clone(),
            self.h_powers.ys.as_poly().clone(),
            self.node_idx.as_poly().clone(),
            self.bf_bits.as_poly().clone(),
            self.selected_node_acc.as_poly().clone(),
            self.blinded_node_acc.xs.as_poly().clone(),
            self.blinded_node_acc.ys.as_poly().clone(),
            self.node_idx_sum_acc.as_poly().clone(),
        ]
    }

    fn _columns_evaluated(&self, zeta: &G::BaseField) -> ProofEvals<G::BaseField> {
        let x_coords = self.x_coords.evaluate(zeta);
        let h_powers = [
            self.h_powers.xs.evaluate(zeta),
            self.h_powers.ys.evaluate(zeta),
        ];
        let node_idx = self.node_idx.evaluate(zeta);
        let bf_bits = self.bf_bits.evaluate(zeta);
        let blinded_node_acc = [
            self.blinded_node_acc.xs.evaluate(zeta),
            self.blinded_node_acc.ys.evaluate(zeta),
        ];
        let selected_node_acc = self.selected_node_acc.evaluate(zeta);
        let node_idx_sum_acc = self.node_idx_sum_acc.evaluate(zeta);
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

impl<C: CurveGroup, G: CurveModel<BaseField = C::ScalarField>>
    ProverPiop<C::ScalarField, WrappedAffine<C>> for PiopProver<AffinePoint<G>>
{
    const N_COLUMNS: usize = 9;
    const N_CONSTRAINTS: usize = 13;
    const N_QUOTIENT_CHUNKS: usize = 3;

    type Commitments = ProofComms<C>;
    type Evaluations = ProofEvals<C::ScalarField>;
    type Instance = AffinePoint<G>;

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
        self.gadgets.iter().flat_map(|g| g.constraints()).collect()
    }

    fn quotient(&self, alphas: &[C::ScalarField]) -> Option<Vec<DensePolynomial<C::ScalarField>>> {
        <Self as ProverPiop<C::ScalarField, WrappedAffine<C>>>::_quotient_chunks(self, alphas)
    }

    fn constraints_lin(&self, zeta: &C::ScalarField) -> Vec<DensePolynomial<C::ScalarField>> {
        self.gadgets
            .iter()
            .flat_map(|g| g.constraints_linearized(zeta))
            .collect()
    }

    fn domain(&self) -> &Domain<C::ScalarField> {
        &self.domain
    }

    fn result(&self) -> Self::Instance {
        self.result
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
