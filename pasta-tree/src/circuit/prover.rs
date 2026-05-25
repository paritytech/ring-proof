use crate::PiopParams;
use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::circuit::{ProofComms, ProofEvals};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ff::PrimeField;
use ark_poly::Evaluations;
use ark_poly::univariate::DensePolynomial;
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::Commitment;
use w3f_plonk_common::Column;
use w3f_plonk_common::FieldColumn;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::ProverGadget;
use w3f_plonk_common::gadgets::booleanity::{BitColumn, Booleanity};
use w3f_plonk_common::gadgets::ec::AffineColumn;
use w3f_plonk_common::gadgets::ec::CondAdd;
use w3f_plonk_common::gadgets::inner_prod::InnerProd;
use w3f_plonk_common::piop::ProverPiop;

pub struct PiopProver<F: PrimeField, G: AffineRepr<BaseField = F>> {
    domain: Domain<F>,
    // `x` coordinates of all the children of a node. Public input.
    x_coords: FieldColumn<F>,
    // `H, 2H, 4H,...,2^sH` Fixed column.
    h_powers: AffineColumn<F, G>,
    // `node_x = self.x_coords[self.node_idx]` Private input.
    node_selector: BitColumn<F>,
    // Bits of the chosen blinding factor. Private input.
    bf_bits: BitColumn<F>,
    node_x_coord: InnerProd<F>,
    blinded_node: CondAdd<F, G>, // blinded_node.acc[0] = (x_i, y_i) = Ci, blinded_node.acc[capacity] = Ci + bf.H = Ci'
    node_selector_bool: Booleanity<F>,
    bf_bits_bool: Booleanity<F>,
}

impl<F: PrimeField, G: AffineRepr<BaseField = F>> PiopProver<F, G> {
    pub fn build(params: &PiopParams<G>, level: LevelWitnessWithBlinding<G>) -> Self {
        let domain = params.domain.clone();
        let x_coords = params.x_coords_column(level.level_witness.x_coords());
        let h_powers = params.h_powers_column();
        let node_selector = params.node_selector(level.level_witness.path_node_idx);
        let bf_bits = params.bf_bits_column(level.bf);

        let node = level.level_witness.path_node();

        let node_x_coord = InnerProd::init(x_coords.clone(), node_selector.col.clone(), &domain);
        let witnessed_x = node.x().unwrap();
        let computed_x = node_x_coord.acc.payload()[domain.capacity - 1];
        assert_eq!(computed_x, witnessed_x);
        // here we witness yi
        let blinded_node = CondAdd::init(bf_bits.clone(), h_powers.clone(), node, &domain);
        assert_eq!(
            blinded_node.seed_plus_sum(),
            (node + params.h * level.bf).into_affine()
        );
        let node_selector_bool = Booleanity::init(node_selector.clone());
        let bf_bits_bool = Booleanity::init(bf_bits.clone());
        // let cond_add_acc_x = FixedCells::init(blinded_node.acc.xs.clone(), &domain);
        // let cond_add_acc_y = FixedCells::init(blinded_node.acc.ys.clone(), &domain);
        // let inner_prod_acc = FixedCells::init(node_x_coord.acc.clone(), &domain);
        Self {
            domain,
            x_coords,
            h_powers,
            node_selector,
            bf_bits,
            node_x_coord,
            blinded_node,
            node_selector_bool,
            bf_bits_bool,
        }
    }

    fn _committed_columns<C: Commitment<F>, Fun: Fn(&DensePolynomial<F>) -> C>(
        &self,
        commit: Fun,
    ) -> ProofComms<F, C> {
        let node_selector = commit(self.node_selector.as_poly());
        let bf_bits = commit(self.bf_bits.as_poly());
        let node_x_coord_acc = commit(self.node_x_coord.acc.as_poly());
        let blinded_node_acc = [
            commit(self.blinded_node.acc.xs.as_poly()),
            commit(self.blinded_node.acc.ys.as_poly()),
        ];
        ProofComms {
            node_selector,
            bf_bits,
            node_x_coord_acc,
            blinded_node_acc,
            phantom: PhantomData,
        }
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn _columns(&self) -> Vec<DensePolynomial<F>> {
        vec![
            self.x_coords.as_poly().clone(),
            self.h_powers.xs.as_poly().clone(),
            self.h_powers.ys.as_poly().clone(),
            self.node_selector.as_poly().clone(),
            self.bf_bits.as_poly().clone(),
            self.node_x_coord.acc.as_poly().clone(),
            self.blinded_node.acc.xs.as_poly().clone(),
            self.blinded_node.acc.ys.as_poly().clone(),
        ]
    }

    fn _columns_evaluated(&self, zeta: &F) -> ProofEvals<F> {
        let x_coords = self.x_coords.evaluate(zeta);
        let h_powers = [
            self.h_powers.xs.evaluate(zeta),
            self.h_powers.ys.evaluate(zeta),
        ];
        let node_selector = self.node_selector.evaluate(zeta);
        let bf_bits = self.bf_bits.evaluate(zeta);
        let blinded_node_acc = [
            self.blinded_node.acc.xs.evaluate(zeta),
            self.blinded_node.acc.ys.evaluate(zeta),
        ];
        let node_x_coord_acc = self.node_x_coord.acc.evaluate(zeta);
        ProofEvals {
            x_coords,
            h_powers,
            node_selector,
            bf_bits,
            node_x_coord_acc,
            blinded_node_acc,
        }
    }
}

impl<F: PrimeField, C: Commitment<F>, G: SWCurveConfig<BaseField = F>> ProverPiop<F, C>
    for PiopProver<F, SwAffine<G>>
{
    const N_CONSTRAINTS: usize = 5;
    type Commitments = ProofComms<F, C>;
    type Evaluations = ProofEvals<F>;
    type Instance = SwAffine<G>;

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
            self.node_x_coord.constraints(),
            self.blinded_node.constraints(),
            self.node_selector_bool.constraints(),
            self.bf_bits_bool.constraints(),
        ]
        .concat()
    }

    fn constraints_lin(&self, zeta: &F) -> Vec<DensePolynomial<F>> {
        vec![
            self.node_x_coord.constraints_linearized(zeta),
            self.blinded_node.constraints_linearized(zeta),
            self.node_selector_bool.constraints_linearized(zeta),
            self.bf_bits_bool.constraints_linearized(zeta),
        ]
        .concat()
    }

    fn domain(&self) -> &Domain<F> {
        &self.domain
    }

    fn result(&self) -> Self::Instance {
        self.blinded_node.seed_plus_sum()
    }
}
