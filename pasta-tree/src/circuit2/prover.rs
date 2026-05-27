use crate::auth_path::node::LevelWitnessWithBlinding;
use crate::circuit2::params::PiopParams;
use crate::circuit2::{ProofComms, ProofEvals};
use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::{Affine as SwAffine, SWCurveConfig};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::Evaluations;
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;
use ark_std::marker::PhantomData;
use ark_std::{vec, vec::Vec};
use w3f_pcs::pcs::Commitment;
use w3f_plonk_common::FieldColumn;
use w3f_plonk_common::domain::Domain;
use w3f_plonk_common::gadgets::ProverGadget;
use w3f_plonk_common::gadgets::booleanity::{BitColumn, Booleanity};
use w3f_plonk_common::gadgets::ec::AffineColumn;
use w3f_plonk_common::gadgets::ec::CondAdd;
use w3f_plonk_common::gadgets::fixed_cells::FixedCells;
use w3f_plonk_common::gadgets::inner_prod::InnerProd;
use w3f_plonk_common::piop::ProverPiop;

// struct Witness<F: PrimeField, G: AffineRepr<BaseField=F>> {
//     // `x` coordinates of all the children of a node. Public input.
//     // `H, 2H, 4H,...,2^sH` Fixed column.
//     points: AffineColumn<F, G>,
//     // `node_x = self.x_coords[self.node_idx]` Private input.
//     // Bits of the chosen blinding factor. Private input.
//     bits: BitColumn<F>,
//     select_part: FieldColumn<F>,
//     inner_prod_acc: DensePolynomial<F>,
//     cond_add_acc_x: DensePolynomial<F>,
//     cond_add_acc_y: DensePolynomial<F>,
// }

pub struct PiopProver<F: PrimeField, G: AffineRepr<BaseField = F>> {
    domain: Domain<F>,
    // `x` coordinates of all the children of a node. Public input.
    // `H, 2H, 4H,...,2^sH` Fixed column.
    points: AffineColumn<F, G>,
    // `node_x = self.x_coords[self.node_idx]` Private input.
    // Bits of the chosen blinding factor. Private input.
    bits: BitColumn<F>,
    select_part: FieldColumn<F>,
    inner_prod_acc: DensePolynomial<F>,
    cond_add_acc_x: DensePolynomial<F>,
    cond_add_acc_y: DensePolynomial<F>,
    // columns: Witness<F, G>,
    gadgets: Vec<Box<dyn ProverGadget<F>>>,
    result: G,
}

impl<G: SWCurveConfig<BaseField: PrimeField>> PiopProver<G::BaseField, SwAffine<G>> {
    pub fn build(
        params: &PiopParams<SwAffine<G>>,
        level: LevelWitnessWithBlinding<SwAffine<G>>,
    ) -> Self {
        let domain = params.domain.clone();
        let points = params.points_column(level.level_witness.siblings);
        let bits = params.bits_column(level.level_witness.path_node_idx, level.bf);
        let bits_bool = Booleanity::init(bits.clone());
        let select_part = params.select_part();
        let inner_prod = InnerProd::init(select_part.clone(), bits.col.clone(), &domain);
        let inner_prod_vals = FixedCells::init(
            inner_prod.acc.clone(),
            &domain,
            G::BaseField::zero(),
            G::BaseField::one(),
        );
        let cond_add = CondAdd::init(bits.clone(), points.clone(), params.seed, &domain);
        let (seed_x, seed_y) = params.seed.xy().unwrap();
        let (result_x, result_y) = cond_add.seed_plus_sum().xy().unwrap();
        let cond_add_vals_x = FixedCells::init(cond_add.acc.xs.clone(), &domain, seed_x, result_x);
        let cond_add_vals_y = FixedCells::init(cond_add.acc.ys.clone(), &domain, seed_y, result_y);

        let inner_prod_acc = inner_prod.acc.as_poly().clone();
        let cond_add_acc_x = cond_add.acc.xs.as_poly().clone();
        let cond_add_acc_y = cond_add.acc.ys.as_poly().clone();
        let result = cond_add.result();

        let mut gadgets: Vec<Box<dyn ProverGadget<G::BaseField>>> = Vec::new();
        gadgets.push(Box::new(inner_prod));
        gadgets.push(Box::new(cond_add));
        gadgets.push(Box::new(bits_bool));
        gadgets.push(Box::new(cond_add_vals_x));
        gadgets.push(Box::new(cond_add_vals_y));
        gadgets.push(Box::new(inner_prod_vals));

        Self {
            domain,

            points,
            bits,
            select_part,

            gadgets,
            inner_prod_acc,
            cond_add_acc_x,
            cond_add_acc_y,
            result,
        }
    }
}

impl<F: PrimeField, C: Commitment<F>, G: SWCurveConfig<BaseField = F>> ProverPiop<F, C>
    for PiopProver<F, SwAffine<G>>
{
    const N_CONSTRAINTS: usize = 7;
    type Commitments = ProofComms<F, C>;
    type Evaluations = ProofEvals<F>;
    type Instance = SwAffine<G>;

    fn committed_columns<Fun: Fn(&DensePolynomial<F>) -> C>(
        &self,
        commit: Fun,
    ) -> Self::Commitments {
        let points_y = commit(self.points.ys.as_poly());
        let bits = commit(self.bits.as_poly());
        let cond_add_acc = [commit(&self.cond_add_acc_x), commit(&self.cond_add_acc_y)];
        let inn_prod_acc = commit(&self.inner_prod_acc);
        ProofComms {
            points_y,
            bits,
            cond_add_acc,
            inn_prod_acc,
            phantom: PhantomData,
        }
    }

    // Should return polynomials in the consistent with
    // Self::Evaluations::to_vec() and Self::Commitments::to_vec().
    fn columns(&self) -> Vec<DensePolynomial<F>> {
        vec![
            self.points.xs.as_poly().clone(),
            self.select_part.as_poly().clone(),
            self.points.ys.as_poly().clone(),
            self.bits.as_poly().clone(),
            self.inner_prod_acc.clone(),
            self.cond_add_acc_x.clone(),
            self.cond_add_acc_y.clone(),
        ]
    }

    fn columns_evaluated(&self, zeta: &F) -> ProofEvals<F> {
        let points = [self.points.xs.evaluate(zeta), self.points.ys.evaluate(zeta)];
        let ring_selector = self.select_part.evaluate(zeta);
        let bits = self.bits.evaluate(zeta);
        let inn_prod_acc = self.inner_prod_acc.evaluate(zeta);
        let cond_add_acc = [
            self.cond_add_acc_x.evaluate(zeta),
            self.cond_add_acc_y.evaluate(zeta),
        ];
        ProofEvals {
            points,
            ring_selector,
            bits,
            inn_prod_acc,
            cond_add_acc,
        }
    }

    fn constraints(&self) -> Vec<Evaluations<F>> {
        self.gadgets.iter().flat_map(|g| g.constraints()).collect()
    }

    fn constraints_lin(&self, zeta: &F) -> Vec<DensePolynomial<F>> {
        self.gadgets
            .iter()
            .flat_map(|g| g.constraints_linearized(zeta))
            .collect()
    }

    fn domain(&self) -> &Domain<F> {
        &self.domain
    }

    fn result(&self) -> Self::Instance {
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IPACommitment;
    use crate::tests::random_witness;
    use ark_bls12_381::G1Projective;
    use ark_ec::CurveGroup;
    use ark_ff::Zero;

    use ark_ed_on_bls12_381_bandersnatch::{Fq, Fr, SWAffine};
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_constraints() {
        let rng = &mut test_rng();

        let domain_size = 512;
        let domain = Domain::<Fq>::new(domain_size, true);

        let node = SWAffine::rand(rng);
        let h = SWAffine::rand(rng);
        let seed = SWAffine::rand(rng);
        let bf = Fr::from(u128::rand(rng));
        let blinded_node = (node + h * bf).into_affine();

        let piop_params = PiopParams::setup(domain, h, seed);
        let witness =
            random_witness(piop_params.max_nodes, node, rng).with_blinding(bf, Fq::zero());
        let piop = PiopProver::build(&piop_params, witness);

        assert!(ProverPiop::<_, IPACommitment<G1Projective>>::constraints_satisfied(&piop));
        assert_eq!(
            ProverPiop::<_, IPACommitment<G1Projective>>::result(&piop),
            blinded_node
        );
    }
}
