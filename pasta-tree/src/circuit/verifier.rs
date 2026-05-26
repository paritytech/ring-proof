use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::Commitment;

use crate::circuit::{ProofComms, ProofEvals};
use w3f_plonk_common::domain::EvaluatedDomain;
use w3f_plonk_common::gadgets::VerifierGadget;
use w3f_plonk_common::gadgets::booleanity::BooleanityValues;
use w3f_plonk_common::gadgets::column_sum::ColumnSumEvals;
use w3f_plonk_common::gadgets::ec::{AffineColumn, CondAddValues};
use w3f_plonk_common::gadgets::equal_cells::EqualCells;
use w3f_plonk_common::gadgets::fixed_cells::FixedCellsValues;
use w3f_plonk_common::gadgets::inner_prod_inv::InnerProdInvValues;
use w3f_plonk_common::piop::VerifierPiop;

pub struct PiopVerifier<F: PrimeField, C: Commitment<F>, G: AffineRepr<BaseField = F>> {
    domain_evals: EvaluatedDomain<F>,
    instance: G,
    x_coords_comm: C,
    h_powers_comm: [C; 2],
    witness_columns: ProofComms<F, C>,
    // Gadget verifiers:
    selected_node: InnerProdInvValues<F>,
    blinded_node: CondAddValues<F, G>,
    node_idx_sum: ColumnSumEvals<F>,
    node_idx_bool: BooleanityValues<F>,
    bf_bits_bool: BooleanityValues<F>,
    node_idx_sum_vals: FixedCellsValues<F>,
    seed_eq_node: EqualCells<F>,
}

impl<F: PrimeField, C: Commitment<F>, G: AffineRepr<BaseField = F>> PiopVerifier<F, C, G> {
    pub fn init(
        instance: G,
        blinded_parent: C,
        domain_evals: EvaluatedDomain<F>,
        h_powers_comm: [C; 2],
        witness_columns: ProofComms<F, C>,
        all_evals: ProofEvals<F>,
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
            col_first: F::zero(),
            col_last: F::one(),
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

impl<F: PrimeField, C: Commitment<F>, G: SWCurveConfig<BaseField = F>> VerifierPiop<F, C>
    for PiopVerifier<F, C, SwAffine<G>>
{
    const N_CONSTRAINTS: usize = 12;
    const N_COLUMNS: usize = 9;

    fn precommitted_columns(&self) -> Vec<C> {
        vec![
            self.x_coords_comm.clone(),
            self.h_powers_comm[0].clone(),
            self.h_powers_comm[1].clone(),
        ]
    }

    fn evaluate_constraints_main(&self) -> Vec<F> {
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
                F::zero(),
            )],
            self.seed_eq_node.evaluate_constraints_main(),
            vec![AffineColumn::<F, SwAffine<G>>::on_curve_eval(self.blinded_node.acc)],
        ]
        .concat()
    }

    fn lin_poly_commitment(&self, agg_coeffs: &[F]) -> (Vec<F>, Vec<C>) {
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

    fn domain_evaluated(&self) -> &EvaluatedDomain<F> {
        &self.domain_evals
    }
}
