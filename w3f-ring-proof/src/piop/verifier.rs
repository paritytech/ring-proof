use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::Commitment;

use w3f_plonk_common::domain::EvaluatedDomain;
use w3f_plonk_common::gadgets::booleanity::BooleanityValues;
use w3f_plonk_common::gadgets::ec::CondAddValues;
use w3f_plonk_common::gadgets::fixed_cells::FixedCellsValues;
use w3f_plonk_common::gadgets::inner_prod::InnerProdValues;
use w3f_plonk_common::gadgets::VerifierGadget;
use w3f_plonk_common::piop::VerifierPiop;

use crate::piop::{FixedColumnsCommitted, RingCommitments};
use crate::RingEvaluations;

pub struct PiopVerifier<F: PrimeField, C: Commitment<F>, P: AffineRepr<BaseField = F>> {
    domain_evals: EvaluatedDomain<F>,
    fixed_columns_committed: FixedColumnsCommitted<F, C>,
    witness_columns_committed: RingCommitments<F, C>,
    // Gadget verifiers:
    booleanity: BooleanityValues<F>,
    inner_prod: InnerProdValues<F>,
    inner_prod_acc: FixedCellsValues<F>,
    cond_add: CondAddValues<F, P>,
    cond_add_acc_x: FixedCellsValues<F>,
    cond_add_acc_y: FixedCellsValues<F>,
}

impl<F: PrimeField, C: Commitment<F>, P: AffineRepr<BaseField = F>> PiopVerifier<F, C, P> {
    pub fn init(
        domain_evals: EvaluatedDomain<F>,
        fixed_columns_committed: FixedColumnsCommitted<F, C>,
        witness_columns_committed: RingCommitments<F, C>,
        all_columns_evaluated: RingEvaluations<F>,
        init: (F, F),
        result: (F, F),
    ) -> Self {
        let cond_add = CondAddValues {
            bitmask: all_columns_evaluated.bits,
            points: (
                all_columns_evaluated.points[0],
                all_columns_evaluated.points[1],
            ),
            not_last: domain_evals.not_last_row,
            acc: (
                all_columns_evaluated.cond_add_acc[0],
                all_columns_evaluated.cond_add_acc[1],
            ),
            _phantom: PhantomData,
        };

        let inner_prod = InnerProdValues {
            a: all_columns_evaluated.ring_selector,
            b: all_columns_evaluated.bits,
            not_last: domain_evals.not_last_row,
            acc: all_columns_evaluated.inn_prod_acc,
        };

        let booleanity = BooleanityValues {
            bits: all_columns_evaluated.bits,
        };

        let cond_add_acc_x = FixedCellsValues {
            col: all_columns_evaluated.cond_add_acc[0],
            col_first: init.0,
            col_last: result.0,
            l_first: domain_evals.l_first,
            l_last: domain_evals.l_last,
        };

        let cond_add_acc_y = FixedCellsValues {
            col: all_columns_evaluated.cond_add_acc[1],
            col_first: init.1,
            col_last: result.1,
            l_first: domain_evals.l_first,
            l_last: domain_evals.l_last,
        };

        let inner_prod_acc = FixedCellsValues {
            col: all_columns_evaluated.inn_prod_acc,
            col_first: F::zero(),
            col_last: F::one(),
            l_first: domain_evals.l_first,
            l_last: domain_evals.l_last,
        };

        Self {
            domain_evals,
            fixed_columns_committed,
            witness_columns_committed,
            inner_prod,
            cond_add,
            booleanity,
            cond_add_acc_x,
            cond_add_acc_y,
            inner_prod_acc,
        }
    }
}

impl<F: PrimeField, C: Commitment<F>, Jubjub: TECurveConfig<BaseField = F>> VerifierPiop<F, C>
    for PiopVerifier<F, C, Affine<Jubjub>>
{
    const N_CONSTRAINTS: usize = 7;
    const N_COLUMNS: usize = 7;

    fn precommitted_columns(&self) -> Vec<C> {
        self.fixed_columns_committed.as_vec()
    }

    fn evaluate_constraints_main(&self) -> Vec<F> {
        vec![
            self.inner_prod.evaluate_constraints_main(),
            self.cond_add.evaluate_constraints_main(),
            self.booleanity.evaluate_constraints_main(),
            self.cond_add_acc_x.evaluate_constraints_main(),
            self.cond_add_acc_y.evaluate_constraints_main(),
            self.inner_prod_acc.evaluate_constraints_main(),
        ]
        .concat()
    }

    fn lin_poly_commitment(&self, agg_coeffs: &[F]) -> (Vec<F>, Vec<C>) {
        assert_eq!(agg_coeffs.len(), Self::N_CONSTRAINTS);

        let inner_prod_acc = self.witness_columns_committed.inn_prod_acc.clone();
        let inner_prod_coeff = agg_coeffs[0] * self.inner_prod.not_last;

        let cond_add_acc_x = self.witness_columns_committed.cond_add_acc[0].clone();
        let cond_add_acc_y = self.witness_columns_committed.cond_add_acc[1].clone();
        let (c_acc_x, c_acc_y) = self.cond_add.acc_coeffs_1();
        let mut cond_add_x_coeff = agg_coeffs[1] * c_acc_x;
        let mut cond_add_y_coeff = agg_coeffs[1] * c_acc_y;
        let (c_acc_x, c_acc_y) = self.cond_add.acc_coeffs_2();
        cond_add_x_coeff += agg_coeffs[2] * c_acc_x;
        cond_add_y_coeff += agg_coeffs[2] * c_acc_y;

        (
            vec![inner_prod_coeff, cond_add_x_coeff, cond_add_y_coeff],
            vec![inner_prod_acc.clone(), cond_add_acc_x, cond_add_acc_y],
        )

        // C::combine(
        //     &[inner_prod_coeff, cond_add_x_coeff, cond_add_y_coeff],
        //     &[inner_prod_acc.clone(), cond_add_acc_x, cond_add_acc_y],
        // )
    }

    fn domain_evaluated(&self) -> &EvaluatedDomain<F> {
        &self.domain_evals
    }
}
