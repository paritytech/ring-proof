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
use w3f_plonk_common::gadgets::ec::CondAddValues;
use w3f_plonk_common::gadgets::inner_prod::InnerProdValues;
use w3f_plonk_common::piop::VerifierPiop;

pub struct PiopVerifier<F: PrimeField, C: Commitment<F>, G: AffineRepr<BaseField = F>> {
    domain_evals: EvaluatedDomain<F>,
    x_coords_comm: C,
    h_powers_comm: [C; 2],
    witness_columns: ProofComms<F, C>,
    // Gadget verifiers:
    node_x_coord: InnerProdValues<F>,
    blinded_node: CondAddValues<F, G>,
    node_selector_bool: BooleanityValues<F>,
    bf_bits_bool: BooleanityValues<F>,
}

impl<F: PrimeField, C: Commitment<F>, G: AffineRepr<BaseField = F>> PiopVerifier<F, C, G> {
    pub fn init(
        _blinded_node: G,
        blinded_parent: C,
        domain_evals: EvaluatedDomain<F>,
        h_powers_comm: [C; 2],
        witness_columns: ProofComms<F, C>,
        all_evals: ProofEvals<F>,
    ) -> Self {
        let node_x_coord = InnerProdValues {
            a: all_evals.x_coords,
            b: all_evals.node_selector,
            not_last: domain_evals.not_last_row,
            acc: all_evals.node_x_coord_acc,
        };

        let blinded_node = CondAddValues {
            bitmask: all_evals.bf_bits,
            points: (all_evals.h_powers[0], all_evals.h_powers[1]),
            not_last: domain_evals.not_last_row,
            acc: (all_evals.blinded_node_acc[0], all_evals.blinded_node_acc[1]),
            _phantom: PhantomData,
        };

        let node_selector_bool = BooleanityValues {
            bits: all_evals.node_selector,
        };

        let bf_bits_bool = BooleanityValues {
            bits: all_evals.bf_bits,
        };

        Self {
            domain_evals,
            x_coords_comm: blinded_parent,
            h_powers_comm,
            witness_columns,
            node_x_coord,
            blinded_node,
            node_selector_bool,
            bf_bits_bool,
        }
    }
}

impl<F: PrimeField, C: Commitment<F>, G: SWCurveConfig<BaseField = F>> VerifierPiop<F, C>
    for PiopVerifier<F, C, SwAffine<G>>
{
    const N_CONSTRAINTS: usize = 5;
    const N_COLUMNS: usize = 8;

    fn precommitted_columns(&self) -> Vec<C> {
        vec![
            self.x_coords_comm.clone(),
            self.h_powers_comm[0].clone(),
            self.h_powers_comm[1].clone(),
        ]
    }

    fn evaluate_constraints_main(&self) -> Vec<F> {
        vec![
            self.node_x_coord.evaluate_constraints_main(),
            self.blinded_node.evaluate_constraints_main(),
            self.node_selector_bool.evaluate_constraints_main(),
            self.bf_bits_bool.evaluate_constraints_main(),
        ]
        .concat()
    }

    fn lin_poly_commitment(&self, agg_coeffs: &[F]) -> (Vec<F>, Vec<C>) {
        assert_eq!(agg_coeffs.len(), Self::N_CONSTRAINTS);

        let node_x_coord_acc = self.witness_columns.node_x_coord_acc.clone();
        let node_x_coord_coeff = agg_coeffs[0] * self.node_x_coord.not_last;

        let blinded_node_acc_x = self.witness_columns.blinded_node_acc[0].clone();
        let blinded_node_acc_y = self.witness_columns.blinded_node_acc[1].clone();
        let (c_acc_x, c_acc_y) = self.blinded_node.acc_coeffs_1();
        let mut blinded_node_x_coeff = agg_coeffs[1] * c_acc_x;
        let mut blinded_node_y_coeff = agg_coeffs[1] * c_acc_y;
        let (c_acc_x, c_acc_y) = self.blinded_node.acc_coeffs_2();
        blinded_node_x_coeff += agg_coeffs[2] * c_acc_x;
        blinded_node_y_coeff += agg_coeffs[2] * c_acc_y;
        (
            vec![
                node_x_coord_coeff,
                blinded_node_x_coeff,
                blinded_node_y_coeff,
            ],
            vec![node_x_coord_acc, blinded_node_acc_x, blinded_node_acc_y],
        )
    }

    fn domain_evaluated(&self) -> &EvaluatedDomain<F> {
        &self.domain_evals
    }
}
