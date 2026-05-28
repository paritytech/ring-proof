use crate::circuit_fat::{ProofComms, ProofEvals};
use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;
use ark_ff::Zero;
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::domain::EvaluatedDomain;
use w3f_plonk_common::gadgets::VerifierGadget;
use w3f_plonk_common::gadgets::booleanity::BooleanityValues;
use w3f_plonk_common::gadgets::column_sum::ColumnSumEvals;
use w3f_plonk_common::gadgets::ec::{AffineColumn, CondAddValues};
use w3f_plonk_common::gadgets::equal_cells::EqualCells;
use w3f_plonk_common::gadgets::fixed_cells::FixedCellsValues;
use w3f_plonk_common::gadgets::inner_prod_inv::InnerProdInvValues;
use w3f_plonk_common::piop::VerifierPiop;

pub struct PiopVerifier<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> {
    domain_evals: EvaluatedDomain<C::ScalarField>,
    instance: G,
    x_coords_comm: WrappedAffine<C>,
    h_powers_comm: [WrappedAffine<C>; 2],
    witness_columns: ProofComms<C>,
    // Gadget verifiers:
    selected_node: InnerProdInvValues<C::ScalarField>,
    blinded_node: CondAddValues<C::ScalarField, G>,
    node_idx_sum: ColumnSumEvals<C::ScalarField>,
    node_idx_bool: BooleanityValues<C::ScalarField>,
    bf_bits_bool: BooleanityValues<C::ScalarField>,
    node_idx_sum_vals: FixedCellsValues<C::ScalarField>,
    seed_eq_node: EqualCells<C::ScalarField>,
}

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> PiopVerifier<C, G> {
    pub fn init(
        instance: G,
        blinded_parent: WrappedAffine<C>,
        domain_evals: EvaluatedDomain<C::ScalarField>,
        h_powers_comm: [WrappedAffine<C>; 2],
        witness_columns: ProofComms<C>,
        all_evals: ProofEvals<C::ScalarField>,
    ) -> Self {
        let selected_node = InnerProdInvValues {
            a: all_evals.x_coords,
            b: all_evals.node_idx,
            not_last: domain_evals.not_last_row,
            acc: all_evals.selected_node_acc,
        };
        let blinded_node = CondAddValues {
            bitmask: all_evals.bf_bits,
            points: (all_evals.h_powers[0], all_evals.h_powers[1]),
            not_last: domain_evals.not_last_row,
            acc: (all_evals.blinded_node_acc[0], all_evals.blinded_node_acc[1]),
            _phantom: PhantomData,
        };
        let node_idx_sum = ColumnSumEvals {
            col: all_evals.node_idx,
            acc: all_evals.node_idx_sum_acc,
            not_last: domain_evals.not_last_row,
        };
        let node_idx_bool = BooleanityValues {
            bits: all_evals.node_idx,
        };
        let bf_bits_bool = BooleanityValues {
            bits: all_evals.bf_bits,
        };
        let node_idx_sum_vals = FixedCellsValues {
            col: all_evals.node_idx_sum_acc,
            col_first: C::ScalarField::zero(),
            col_last: C::ScalarField::one(),
            l_first: domain_evals.l_first,
            l_last: domain_evals.l_last,
        };
        let seed_eq_node = EqualCells {
            a: selected_node.acc,
            b: blinded_node.acc.0,
            li: domain_evals.l_first,
        };
        Self {
            instance,
            domain_evals,
            x_coords_comm: blinded_parent,
            h_powers_comm,
            witness_columns,
            // gadgets
            selected_node,
            blinded_node,
            node_idx_sum,
            node_idx_bool,
            bf_bits_bool,
            node_idx_sum_vals,
            seed_eq_node,
        }
    }
}

impl<C: CurveGroup, G: SWCurveConfig<BaseField = C::ScalarField>>
    VerifierPiop<C::ScalarField, WrappedAffine<C>> for PiopVerifier<C, SwAffine<G>>
{
    const N_CONSTRAINTS: usize = 13;
    const N_COLUMNS: usize = 9;

    fn precommitted_columns(&self) -> Vec<WrappedAffine<C>> {
        vec![
            self.x_coords_comm.clone(),
            self.h_powers_comm[0].clone(),
            self.h_powers_comm[1].clone(),
        ]
    }

    fn evaluate_constraints_main(&self) -> Vec<C::ScalarField> {
        let (x, y) = self.instance.xy().unwrap();
        vec![
            self.selected_node.evaluate_constraints_main(),
            self.blinded_node.evaluate_constraints_main(),
            self.node_idx_sum.evaluate_constraints_main(),
            self.node_idx_bool.evaluate_constraints_main(),
            self.bf_bits_bool.evaluate_constraints_main(),
            self.node_idx_sum_vals.evaluate_constraints_main(),
            vec![FixedCellsValues::evaluate_for_cell(
                self.blinded_node.acc.0,
                self.domain_evals.l_last,
                x,
            )],
            vec![FixedCellsValues::evaluate_for_cell(
                self.blinded_node.acc.1,
                self.domain_evals.l_last,
                y,
            )],
            vec![FixedCellsValues::evaluate_for_cell(
                self.selected_node.acc,
                self.domain_evals.l_last,
                C::ScalarField::zero(),
            )],
            self.seed_eq_node.evaluate_constraints_main(),
            vec![AffineColumn::<C::ScalarField, SwAffine<G>>::on_curve_eval(
                self.blinded_node.acc,
            )],
            vec![FixedCellsValues::evaluate_for_cell(
                self.selected_node.a,
                self.domain_evals.l_last,
                C::ScalarField::one(),
            )],
        ]
        .concat()
    }

    fn lin_poly_commitment(
        &self,
        agg_coeffs: &[C::ScalarField],
    ) -> (Vec<C::ScalarField>, Vec<WrappedAffine<C>>) {
        assert_eq!(agg_coeffs.len(), Self::N_CONSTRAINTS);

        let selected_node_acc = self.witness_columns.selected_node_acc.clone();
        let selected_node_coeff = -agg_coeffs[0] * self.selected_node.not_last;

        let blinded_node_acc_x = self.witness_columns.blinded_node_acc[0].clone();
        let blinded_node_acc_y = self.witness_columns.blinded_node_acc[1].clone();
        let (c_acc_x, c_acc_y) = self.blinded_node.acc_coeffs_1();
        let mut blinded_node_x_coeff = agg_coeffs[1] * c_acc_x;
        let mut blinded_node_y_coeff = agg_coeffs[1] * c_acc_y;
        let (c_acc_x, c_acc_y) = self.blinded_node.acc_coeffs_2();
        blinded_node_x_coeff += agg_coeffs[2] * c_acc_x;
        blinded_node_y_coeff += agg_coeffs[2] * c_acc_y;

        let node_idx_sum_acc = self.witness_columns.node_idx_sum_acc.clone();
        let node_idx_sum_coeff = agg_coeffs[3] * self.node_idx_sum.not_last;
        (
            vec![
                selected_node_coeff,
                blinded_node_x_coeff,
                blinded_node_y_coeff,
                node_idx_sum_coeff,
            ],
            vec![
                selected_node_acc,
                blinded_node_acc_x,
                blinded_node_acc_y,
                node_idx_sum_acc,
            ],
        )
    }

    fn domain_evaluated(&self) -> &EvaluatedDomain<C::ScalarField> {
        &self.domain_evals
    }
}
