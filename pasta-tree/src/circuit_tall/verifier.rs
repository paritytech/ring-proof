use crate::circuit_tall::{ProofComms, ProofEvals};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
// use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use crate::{AffinePoint, CurveModel};
use ark_ff::{One, Zero};
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_plonk_common::domain::EvaluatedDomain;
use w3f_plonk_common::gadgets::VerifierGadget;
use w3f_plonk_common::gadgets::booleanity::BooleanityValues;
use w3f_plonk_common::gadgets::ec::CondAddValues;
use w3f_plonk_common::gadgets::fixed_cells::FixedCellsValues;
use w3f_plonk_common::gadgets::inner_prod::InnerProdValues;
use w3f_plonk_common::piop::VerifierPiop;

pub struct PiopVerifier<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> {
    domain_evals: EvaluatedDomain<C::ScalarField>,

    points_x: WrappedAffine<C>,
    select_part: WrappedAffine<C>,
    witness_cols: ProofComms<C>,

    // Gadget verifiers:
    booleanity: BooleanityValues<C::ScalarField>,
    inner_prod: InnerProdValues<C::ScalarField>,
    inner_prod_acc: FixedCellsValues<C::ScalarField>,
    cond_add: CondAddValues<G::BaseField, G>,
    cond_add_acc_x: FixedCellsValues<C::ScalarField>,
    cond_add_acc_y: FixedCellsValues<C::ScalarField>,
}

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> PiopVerifier<C, G> {
    pub fn init(
        domain_evals: EvaluatedDomain<C::ScalarField>,
        points_x: WrappedAffine<C>,
        select_part: WrappedAffine<C>,
        witness_cols: ProofComms<C>,
        evals: ProofEvals<C::ScalarField>,
        seed: G,
        result: G,
    ) -> Self {
        let cond_add = CondAddValues {
            bitmask: evals.bits,
            points: (evals.points[0], evals.points[1]),
            not_last: domain_evals.not_last_row,
            acc: (evals.cond_add_acc[0], evals.cond_add_acc[1]),
            _phantom: PhantomData,
        };

        let inner_prod = InnerProdValues {
            a: evals.ring_selector,
            b: evals.bits,
            not_last: domain_evals.not_last_row,
            acc: evals.inn_prod_acc,
        };

        let booleanity = BooleanityValues { bits: evals.bits };

        let (seed_x, seed_y) = seed.xy().unwrap();
        let (res_x, res_y) = (seed + result).into_affine().xy().unwrap();

        let cond_add_acc_x = FixedCellsValues {
            col: evals.cond_add_acc[0],
            l_i: vec![domain_evals.l_first, domain_evals.l_last],
            col_i: vec![seed_x, res_x],
        };

        let cond_add_acc_y = FixedCellsValues {
            col: evals.cond_add_acc[1],
            l_i: vec![domain_evals.l_first, domain_evals.l_last],
            col_i: vec![seed_y, res_y],
        };

        let inner_prod_acc = FixedCellsValues {
            col: evals.inn_prod_acc,
            l_i: vec![domain_evals.l_first, domain_evals.l_last],
            col_i: vec![C::ScalarField::zero(), C::ScalarField::one()],
        };

        Self {
            domain_evals,
            points_x,
            select_part,
            witness_cols,
            booleanity,
            inner_prod,
            inner_prod_acc,
            cond_add,
            cond_add_acc_x,
            cond_add_acc_y,
        }
    }
}

impl<C: CurveGroup, G: CurveModel<BaseField = C::ScalarField>>
    VerifierPiop<C::ScalarField, WrappedAffine<C>> for PiopVerifier<C, AffinePoint<G>>
{
    const N_COLUMNS: usize = 7;
    const N_CONSTRAINTS: usize = 7;

    fn precommitted_columns(&self) -> Vec<WrappedAffine<C>> {
        vec![self.points_x.clone(), self.select_part.clone()]
    }

    fn evaluate_constraints_main(&self) -> Vec<C::ScalarField> {
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

    fn lin_poly_commitment(
        &self,
        alphas: &[C::ScalarField],
    ) -> (Vec<C::ScalarField>, Vec<WrappedAffine<C>>) {
        assert_eq!(alphas.len(), Self::N_CONSTRAINTS);

        let inner_prod_acc = self.witness_cols.inn_prod_acc.clone();
        let inner_prod_coeff = alphas[0] * self.inner_prod.not_last;

        let cond_add_acc_x = self.witness_cols.cond_add_acc[0].clone();
        let cond_add_acc_y = self.witness_cols.cond_add_acc[1].clone();
        let (c_acc_x, c_acc_y) = self.cond_add.acc_coeffs_1();
        let mut cond_add_x_coeff = alphas[1] * c_acc_x;
        let mut cond_add_y_coeff = alphas[1] * c_acc_y;
        let (c_acc_x, c_acc_y) = self.cond_add.acc_coeffs_2();
        cond_add_x_coeff += alphas[2] * c_acc_x;
        cond_add_y_coeff += alphas[2] * c_acc_y;
        (
            vec![inner_prod_coeff, cond_add_x_coeff, cond_add_y_coeff],
            vec![inner_prod_acc.clone(), cond_add_acc_x, cond_add_acc_y],
        )
    }

    fn domain_evaluated(&self) -> &EvaluatedDomain<C::ScalarField> {
        &self.domain_evals
    }
}
