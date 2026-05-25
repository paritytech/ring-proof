use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ec::twisted_edwards::{Affine as TeAffine, TECurveConfig};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Evaluations;
use ark_std::marker::PhantomData;

use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::Commitment;

use crate::piop::params::PiopParams;
use crate::piop::FixedColumns;
use crate::piop::{RingCommitments, RingEvaluations};
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::booleanity::{BitColumn, Booleanity};
use w3f_plonk_common::gadgets::ec::AffineColumn;
use w3f_plonk_common::gadgets::ec::CondAdd;
use w3f_plonk_common::gadgets::fixed_cells::FixedCells;
use w3f_plonk_common::gadgets::inner_prod::InnerProd;
use w3f_plonk_common::gadgets::ProverGadget;
use w3f_plonk_common::piop::ProverPiop;
use w3f_plonk_common::FieldColumn;

// The 'table': columns representing the execution trace of the computation
// and the constraints -- polynomials that vanish on every 2 consecutive rows.
pub struct PiopProver<F: PrimeField, G: AffineRepr<BaseField = F>> {
    domain: Domain<F>,
    /// Advice (public input) columns
    points: AffineColumn<F, G>,
    ring_selector: FieldColumn<F>,
    // Private input column.
    bits: BitColumn<F>,
    // Gadgets:
    booleanity: Booleanity<F>,
    inner_prod: InnerProd<F>,
    inner_prod_acc: FixedCells<F>,
    cond_add: CondAdd<F, G>,
    cond_add_acc_x: FixedCells<F>,
    cond_add_acc_y: FixedCells<F>,
}

impl<F: PrimeField, G: AffineRepr<BaseField = F>> PiopProver<F, G> {
    pub fn build(
        params: &PiopParams<G>,
        fixed_columns: FixedColumns<F, G>,
        prover_index_in_keys: usize,
        secret: G::ScalarField,
    ) -> Self {
        let domain = params.domain.clone();
        let FixedColumns {
            points,
            ring_selector,
        } = fixed_columns;
        let bits = Self::bits_column(&params, prover_index_in_keys, secret);
        let inner_prod = InnerProd::init(ring_selector.clone(), bits.col.clone(), &domain);
        let cond_add = CondAdd::init(bits.clone(), points.clone(), params.seed, &domain);
        let booleanity = Booleanity::init(bits.clone());
        let cond_add_acc_x = FixedCells::init(cond_add.acc.xs.clone(), &domain);
        let cond_add_acc_y = FixedCells::init(cond_add.acc.ys.clone(), &domain);
        let inner_prod_acc = FixedCells::init(inner_prod.acc.clone(), &domain);
        Self {
            domain,
            points,
            ring_selector,
            bits,
            inner_prod_acc,
            cond_add_acc_x,
            cond_add_acc_y,
            booleanity,
            inner_prod,
            cond_add,
        }
    }

    // TODO: move to params?
    fn bits_column(
        params: &PiopParams<G>,
        index_in_keys: usize,
        secret: G::ScalarField,
    ) -> BitColumn<F> {
        let mut keyset_part = vec![false; params.keyset_part_size];
        keyset_part[index_in_keys] = true;
        let scalar_part = params.scalar_part(secret);
        let bits = [keyset_part, scalar_part].concat();
        assert_eq!(bits.len(), params.domain.capacity - 1);
        BitColumn::init(bits, &params.domain)
    }

    fn _committed_columns<C: Commitment<F>, Fun: Fn(&DensePolynomial<F>) -> C>(
        &self,
        commit: Fun,
    ) -> RingCommitments<F, C> {
        let bits = commit(self.bits.as_poly());
        let cond_add_acc = [
            commit(self.cond_add.acc.xs.as_poly()),
            commit(self.cond_add.acc.ys.as_poly()),
        ];
        let inn_prod_acc = commit(self.inner_prod.acc.as_poly());
        RingCommitments {
            bits,
            cond_add_acc,
            inn_prod_acc,
            phantom: PhantomData,
        }
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn _columns(&self) -> Vec<DensePolynomial<F>> {
        vec![
            self.points.xs.as_poly().clone(),
            self.points.ys.as_poly().clone(),
            self.ring_selector.as_poly().clone(),
            self.bits.as_poly().clone(),
            self.inner_prod.acc.as_poly().clone(),
            self.cond_add.acc.xs.as_poly().clone(),
            self.cond_add.acc.ys.as_poly().clone(),
        ]
    }

    fn _columns_evaluated(&self, zeta: &F) -> RingEvaluations<F> {
        let points = [self.points.xs.evaluate(zeta), self.points.ys.evaluate(zeta)];
        let ring_selector = self.ring_selector.evaluate(zeta);
        let bits = self.bits.evaluate(zeta);
        let inn_prod_acc = self.inner_prod.acc.evaluate(zeta);
        let cond_add_acc = [
            self.cond_add.acc.xs.evaluate(zeta),
            self.cond_add.acc.ys.evaluate(zeta),
        ];
        RingEvaluations {
            points,
            ring_selector,
            bits,
            inn_prod_acc,
            cond_add_acc,
        }
    }
}

impl<F, C, Curve> ProverPiop<F, C> for PiopProver<F, TeAffine<Curve>>
where
    F: PrimeField,
    C: Commitment<F>,
    Curve: TECurveConfig<BaseField = F>,
{
    const N_CONSTRAINTS: usize = 7;

    type Commitments = RingCommitments<F, C>;
    type Evaluations = RingEvaluations<F>;
    type Instance = TeAffine<Curve>;

    fn committed_columns<Fun: Fn(&DensePolynomial<F>) -> C>(
        &self,
        commit: Fun,
    ) -> Self::Commitments {
        self._committed_columns(commit)
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn columns(&self) -> Vec<DensePolynomial<F>> {
        self._columns()
    }

    fn columns_evaluated(&self, zeta: &F) -> Self::Evaluations {
        self._columns_evaluated(zeta)
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        vec![
            self.inner_prod.constraints(),
            self.cond_add.constraints(),
            self.booleanity.constraints(),
            self.cond_add_acc_x.constraints(),
            self.cond_add_acc_y.constraints(),
            self.inner_prod_acc.constraints(),
        ]
        .concat()
    }

    fn constraints_lin(&self, zeta: &F) -> Vec<DensePolynomial<F>> {
        vec![
            self.inner_prod.constraints_linearized(zeta),
            self.cond_add.constraints_linearized(zeta),
            self.booleanity.constraints_linearized(zeta),
            self.cond_add_acc_x.constraints_linearized(zeta),
            self.cond_add_acc_y.constraints_linearized(zeta),
            self.inner_prod_acc.constraints_linearized(zeta),
        ]
        .concat()
    }

    fn domain(&self) -> &Domain<F> {
        &self.domain
    }

    fn result(&self) -> Self::Instance {
        self.cond_add.result()
    }
}

impl<F, C, Curve> ProverPiop<F, C> for PiopProver<F, SwAffine<Curve>>
where
    F: PrimeField,
    C: Commitment<F>,
    Curve: SWCurveConfig<BaseField = F>,
{
    const N_CONSTRAINTS: usize = 7;

    type Commitments = RingCommitments<F, C>;
    type Evaluations = RingEvaluations<F>;
    type Instance = SwAffine<Curve>;

    fn committed_columns<Fun: Fn(&DensePolynomial<F>) -> C>(
        &self,
        commit: Fun,
    ) -> Self::Commitments {
        self._committed_columns(commit)
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn columns(&self) -> Vec<DensePolynomial<F>> {
        self._columns()
    }

    fn columns_evaluated(&self, zeta: &F) -> Self::Evaluations {
        self._columns_evaluated(zeta)
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        vec![
            self.inner_prod.constraints(),
            self.cond_add.constraints(),
            self.booleanity.constraints(),
            self.cond_add_acc_x.constraints(),
            self.cond_add_acc_y.constraints(),
            self.inner_prod_acc.constraints(),
        ]
        .concat()
    }

    fn constraints_lin(&self, zeta: &F) -> Vec<DensePolynomial<F>> {
        vec![
            self.inner_prod.constraints_linearized(zeta),
            self.cond_add.constraints_linearized(zeta),
            self.booleanity.constraints_linearized(zeta),
            self.cond_add_acc_x.constraints_linearized(zeta),
            self.cond_add_acc_y.constraints_linearized(zeta),
            self.inner_prod_acc.constraints_linearized(zeta),
        ]
        .concat()
    }

    fn domain(&self) -> &Domain<F> {
        &self.domain
    }

    fn result(&self) -> Self::Instance {
        self.cond_add.result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index;
    use crate::tests::setup;
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq, Fr};
    use ark_std::{test_rng, UniformRand};
    use w3f_pcs::pcs::id::WrappedPolynomial;
    use w3f_pcs::pcs::IdentityCommitment;
    use w3f_plonk_common::test_helpers::random_vec;

    #[test]
    fn test_constraints() {
        let rng = &mut test_rng();

        let log_n = 9;
        let n = 1 << log_n;

        let (pcs_params, piop_params) = setup::<_, IdentityCommitment>(rng, n);
        let pks = random_vec::<EdwardsAffine, _>(piop_params.keyset_part_size, rng);
        let (prover_key, _verifier_key) =
            index::<_, IdentityCommitment, _>(&pcs_params, &piop_params, &pks);
        let fixed_columns = prover_key.fixed_columns.clone();
        let piop: PiopProver<Fq, EdwardsAffine> =
            PiopProver::build(&piop_params, fixed_columns, 1, Fr::rand(rng));
        assert!(ProverPiop::<Fq, WrappedPolynomial<Fq>>::constraints_satisfied(&piop));
    }
}
