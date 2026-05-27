use crate::circuit2::params::PiopParams;
use crate::circuit2::{ProofComms, ProofEvals};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, Zero};
use ark_std::UniformRand;
use ark_std::rand::Rng;
use w3f_pcs::aggregation::multiple::ShplonkTranscript;
use w3f_pcs::pcs::PCS;
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::AggregateProof;
use w3f_plonk_common::PiopProof;
use w3f_plonk_common::domain::Domain;

pub mod auth_path;
// pub mod circuit;
pub mod circuit2;
// pub mod level;
pub mod prover;
pub mod verifier;

type IPACommitment<C> = <HidingIpa<C> as PCS<<C as PrimeGroup>::ScalarField>>::C;

pub struct CycleSideParams<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> {
    pcs_params: HidingIpa<C>,
    piop_params: PiopParams<G>,
}

pub struct CycleParams<
    C0: CurveGroup,
    C1: CurveGroup<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
> {
    c0_params: CycleSideParams<C0, C1::Affine>,
    c1_params: CycleSideParams<C1, C0::Affine>,
}

#[derive(Clone)]
pub struct CycleSideProof<F: PrimeField, C: CurveGroup<ScalarField = F>> {
    piop_proofs:
        Vec<PiopProof<F, WrappedAffine<C>, ProofComms<F, WrappedAffine<C>>, ProofEvals<F>>>,
    pcs_proof: AggregateProof<F, HidingIpa<C>>,
    todo: Coeffs<F>,
}

#[derive(Clone)]
pub struct CurveTreeProof<
    F0: PrimeField,
    F1: PrimeField,
    C0: CurveGroup<ScalarField = F0>,
    C1: CurveGroup<ScalarField = F1>,
> {
    c0_proof: CycleSideProof<F0, C0>,
    c1_proof: CycleSideProof<F1, C1>,
}

impl<F0, F1, C0, C1> CycleParams<C0, C1>
where
    F0: PrimeField,
    F1: PrimeField,
    C0: CurveGroup<BaseField = F1, ScalarField = F0>,
    C1: CurveGroup<BaseField = F0, ScalarField = F1>,
{
    pub fn setup<R: Rng>(domain_size: usize, rng: &mut R) -> Self {
        let setup_degree = 3 * domain_size;
        let c0_pcs_params = HidingIpa::<C0>::setup(setup_degree, rng);
        let c1_pcs_params = HidingIpa::<C1>::setup(setup_degree, rng);
        let c0_domain = Domain::<C0::ScalarField>::new(domain_size, true);
        let c0_piop_params = PiopParams::setup(c0_domain, c1_pcs_params.h, C1::Affine::rand(rng));
        let c1_domain = Domain::<C1::ScalarField>::new(domain_size, true);
        let c1_piop_params = PiopParams::setup(c1_domain, c0_pcs_params.h, C0::Affine::rand(rng));
        Self {
            c0_params: CycleSideParams {
                pcs_params: c0_pcs_params,
                piop_params: c0_piop_params,
            },
            c1_params: CycleSideParams {
                pcs_params: c1_pcs_params,
                piop_params: c1_piop_params,
            },
        }
    }
}

impl<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>> CycleSideParams<C, G> {
    pub fn commit_x_coords(
        &self,
        child_x_coords: Vec<G::BaseField>,
        bf: C::ScalarField,
    ) -> Result<WrappedAffine<C>, ()> {
        let x_coords = self.piop_params.commit_x_coords(child_x_coords);
        let x_parent = self.pcs_params.commit_hiding(x_coords.as_poly(), bf);
        x_parent
    }

    pub fn commit_selector(&self) -> WrappedAffine<C> {
        let selector = self.piop_params.select_part();
        self.pcs_params
            .commit_hiding(selector.as_poly(), C::ScalarField::zero())
            .unwrap()
    }

    // pub fn commit_x_coords(
    //     &self,
    //     children_x_coords: Vec<C::ScalarField>,
    //     bf: C::ScalarField,
    // ) -> Result<WrappedAffine<C>, ()> {
    //     let x_coords = self.piop_params.x_coords_column(children_x_coords);
    //     Ok(self.pcs_params.commit_hiding(x_coords.as_poly(), bf)?)
    // }

    // pub fn commit_h_powers(&self) -> [IPACommitment<C>; 2] {
    //     let h_powers = self.piop_params.h_powers_column();
    //     let h_powers = [
    //         self.pcs_params
    //             .commit_hiding(h_powers.xs.as_poly(), C::ScalarField::zero())
    //             .unwrap(),
    //         self.pcs_params
    //             .commit_hiding(h_powers.ys.as_poly(), C::ScalarField::zero())
    //             .unwrap(),
    //     ];
    //     h_powers
    // }
}

#[derive(Debug, PartialEq)]
pub enum CycleSide<C0, C1> {
    C0(C0),
    C1(C1),
}

#[derive(Clone)]
pub struct Coeffs<F: PrimeField>(F, F);
impl<F: PrimeField, CS: PCS<F>> ShplonkTranscript<F, CS> for Coeffs<F> {
    fn get_gamma(&mut self) -> F {
        self.0
    }

    fn commit_to_q(&mut self, _q: &CS::C) {}

    fn get_zeta(&mut self) -> F {
        self.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AdditiveGroup;
    use ark_ec::scalar_mul::glv::GLVConfig;
    use ark_ec::scalar_mul::wnaf::WnafContext;
    use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_ff::{BigInteger, Field, Zero};
    use ark_pallas::PallasConfig;
    use ark_poly::DenseUVPolynomial;
    use ark_std::rand::Rng;
    use ark_std::{UniformRand, cfg_iter_mut, end_timer, start_timer, test_rng};
    use ark_vesta::VestaConfig;
    use w3f_pcs::Poly;
    use w3f_pcs::pcs::PCS;
    use w3f_pcs::pcs::PcsParams;
    use w3f_pcs::pcs::ipa::IPA;
    use w3f_plonk_common::test_helpers::random_vec;

    use crate::auth_path::node::LevelWitness;
    use crate::auth_path::path::AuthenticationPath;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    type PallasIPA = IPA<ark_pallas::Projective>;

    pub fn random_witness<G: AffineRepr<BaseField: PrimeField>, R: Rng>(
        capacity: usize,
        path_node: G,
        rng: &mut R,
    ) -> LevelWitness<G> {
        let mut nodes = random_vec::<G, _>(capacity, rng);
        let i = rng.gen_range(0..capacity);
        nodes[i] = path_node;
        LevelWitness {
            siblings: nodes,
            path_node_idx: i,
        }
    }

    pub fn random_nodes<C: CurveGroup, G: AffineRepr<BaseField = C::ScalarField>, R: Rng>(
        params: &CycleSideParams<C, G>,
        path_node: G,
        rng: &mut R,
    ) -> (C::Affine, LevelWitness<G>) {
        let level_witness = random_witness(params.piop_params.max_nodes, path_node, rng);
        let parent = level_witness.compute_parent(params).unwrap();
        (parent, level_witness)
    }

    pub fn random_path<
        C0: CurveGroup,
        C1: CurveGroup<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
        R: Rng,
    >(
        params: &CycleParams<C0, C1>,
        length: usize,
        rng: &mut R,
    ) -> (
        C0::Affine,
        AuthenticationPath<C0, C1>,
        CycleSide<C0::Affine, C1::Affine>,
    ) {
        let c0_len = (length + 1) / 2;
        let c1_len = length / 2;
        debug_assert_eq!(c0_len + c1_len, length);
        let mut c0_path = Vec::with_capacity(c0_len);
        let mut c1_path = Vec::with_capacity(c1_len);

        let leaf = C0::Affine::rand(rng);
        let mut c0_path_node = leaf;
        for _ in 0..c1_len {
            let (parent_on_c1, c0_nodes) = random_nodes(&params.c1_params, c0_path_node, rng);
            let (parent_on_c0, c1_nodes) = random_nodes(&params.c0_params, parent_on_c1, rng);
            c0_path_node = parent_on_c0;
            c0_path.push(c0_nodes);
            c1_path.push(c1_nodes);
        }

        let root = if c0_len > c1_len {
            let (root_on_c1, c0_nodes) = random_nodes(&params.c1_params, c0_path_node, rng);
            c0_path.push(c0_nodes);
            CycleSide::C1(root_on_c1)
        } else {
            CycleSide::C0(c0_path_node)
        };

        let path = AuthenticationPath { c0_path, c1_path };
        (leaf, path, root)
    }

    fn _test_proof<F0, F1, C0, C1>(log_n: usize, height: usize)
    where
        F0: PrimeField,
        F1: PrimeField,
        C0: SWCurveConfig<BaseField = F1, ScalarField = F0>,
        C1: SWCurveConfig<BaseField = F0, ScalarField = F1>,
    {
        let rng = &mut test_rng();

        let domain_size = 1 << log_n;
        let params = CycleParams::<Projective<C0>, Projective<C1>>::setup(domain_size, rng);
        let (_leaf, path, wrapped_root) = random_path(&params, height, rng);
        let root = match wrapped_root {
            CycleSide::C0(root) => root, //TODO: panics on odd height
            _ => panic!(),
        };

        let max_nodes = params.c0_params.piop_params.max_nodes;
        let t_prove = start_timer!(|| format!(
            "Proving CurveTree membership, H={height}, M={}, C={}, C^{height}={}",
            domain_size,
            max_nodes,
            max_nodes.pow(height as u32)
        ));
        let (auth_path, proof) = params.prove(path, rng);
        end_timer!(t_prove);

        let t_verify = start_timer!(|| "Verifying CurveTree opening");
        let valid = params.verify(auth_path, proof, root);
        end_timer!(t_verify);
        assert!(valid);
    }

    // cargo test test_curve_tree_proof --release --features="print-trace" -- --show-output
    // cargo test test_curve_tree_proof --release --features="print-trace parallel" -- --show-output
    #[test]
    fn test_curve_tree_proof() {
        _test_proof::<_, _, PallasConfig, VestaConfig>(9, 4);
    }

    fn _bench_msm<C: CurveGroup>(log_n: u32) {
        let rng = &mut test_rng();
        let n = 2usize.pow(log_n);
        let (scalars, bases): (Vec<_>, Vec<_>) = (0..n)
            .map(|_| (C::ScalarField::rand(rng), C::Affine::rand(rng)))
            .unzip();
        let t_msm = start_timer!(|| format!(
            "log(n)={log_n}, MSM on {}",
            ark_std::any::type_name::<C::Config>()
        ));
        let _res = C::msm(&bases, &scalars);
        end_timer!(t_msm);
    }

    // cargo test bench_msms --release --features="print-trace" -- --show-output
    // qcargo test bench_msms --release --features="parallel print-trace" -- --show-output
    #[test]
    fn bench_msms() {
        let log_n = 9;

        _bench_msm::<ark_pallas::Projective>(log_n);
        _bench_msm::<ark_pallas::Projective>(log_n + 1);
        // _bench_msm::<ark_vesta::Projective>(log_n);
        // _bench_msm::<ark_bls12_381::G1Projective>(log_n);
        // _bench_folding::<ark_pallas::Affine>(log_n);
        // _bench_folding::<ark_pallas::Affine>(log_n + 1);
        _bench_folding(log_n);
        _bench_folding(log_n + 1);

        let rng = &mut test_rng();
        let n = 2usize.pow(log_n);

        let n3 = 3 * n;
        let pcs_params = PallasIPA::setup(n3, rng);

        let p = Poly::<ark_pallas::Fr>::rand(n, rng);
        let t_ipa_commit = start_timer!(|| format!("IPA commitment to a degree {n} polynomial"));
        let _c = PallasIPA::commit(&pcs_params.ck(), &p);
        end_timer!(t_ipa_commit);

        let p = Poly::<ark_pallas::Fr>::rand(n3, rng);
        let t_ipa_commit = start_timer!(|| format!("IPA commitment to a degree 3*{n} polynomial"));
        let _c = PallasIPA::commit(&pcs_params.ck(), &p);
        end_timer!(t_ipa_commit);
    }

    fn mul_endo_wnaf(
        p: ark_pallas::Projective,
        k1: (bool, ark_pallas::Fr),
        k2: (bool, ark_pallas::Fr),
    ) -> ark_pallas::Projective {
        let mut p1 = p;
        let mut p2 = PallasConfig::endomorphism(&p);
        if !k1.0 {
            p1 = -p1;
        }
        if !k2.0 {
            p2 = -p2;
        }
        let w_size = 4;
        let wnaf = WnafContext::new(w_size);
        let p1_table = wnaf.table(p1);
        let p2_table = wnaf.table(p2);
        let k1_wnaf = k1.1.into_bigint().find_wnaf(w_size).unwrap();
        let mut k2_wnaf = k2.1.into_bigint().find_wnaf(w_size).unwrap();
        k2_wnaf.resize(k1_wnaf.len(), 0);

        let mut result = ark_pallas::Projective::zero();
        let mut found_non_zero = false;
        for (n1, n2) in k1_wnaf.into_iter().zip(k2_wnaf).rev() {
            if found_non_zero {
                result.double_in_place();
            }

            if n1 != 0 || n2 != 0 {
                found_non_zero = true;
                if n1 > 0 {
                    result += &p1_table[(n1 / 2) as usize];
                }
                if n1 < 0 {
                    result -= &p1_table[((-n1) / 2) as usize];
                }
                if n2 > 0 {
                    result += &p2_table[(n2 / 2) as usize];
                }
                if n2 < 0 {
                    result -= &p2_table[((-n2) / 2) as usize];
                }
            }
        }
        result
    }

    fn _bench_folding(log_n: u32) {
        let rng = &mut test_rng();
        let n = 2usize.pow(log_n);
        let (l, r): (Vec<ark_pallas::Affine>, Vec<ark_pallas::Affine>) = (0..n)
            .map(|_| (ark_pallas::Affine::rand(rng), ark_pallas::Affine::rand(rng)))
            .unzip();
        let x = ark_pallas::Fr::rand(rng);
        let _timer = start_timer!(|| format!("Naive folding, log(n) = {log_n}"));
        let res: Vec<ark_pallas::Projective> = ark_std::cfg_iter!(l)
            .zip(r.clone())
            .map(|(l, r)| r * x + l)
            .collect();
        end_timer!(_timer);

        let _timer = start_timer!(|| format!("Naive folding with endo, log(n) = {log_n}"));
        let res_: Vec<ark_pallas::Projective> = ark_std::cfg_into_iter!(l.clone())
            .zip(ark_std::cfg_into_iter!(r.clone()))
            .map(|(l, r)| l + <PallasConfig as GLVConfig>::glv_mul_affine(r, x))
            .collect();
        end_timer!(_timer);
        assert_eq!(res_, res);

        let _timer =
            start_timer!(|| format!("Naive folding with endo and w-NAF, log(n) = {log_n}"));
        let ((sgn_k1, k1), (sgn_k2, k2)) = PallasConfig::scalar_decomposition(x);
        let res_: Vec<ark_pallas::Projective> = ark_std::cfg_into_iter!(l)
            .zip(ark_std::cfg_iter!(r))
            .map(|(l, r)| l + mul_endo_wnaf(r.into_group(), (sgn_k1, k1), (sgn_k2, k2)))
            .collect();
        end_timer!(_timer);
        assert_eq!(res_, res);
    }

    fn batch_double_affine<C: GLVConfig>(bases: Vec<Affine<C>>) -> Vec<Affine<C>> {
        let mut denoms: Vec<C::BaseField> = ark_std::cfg_iter!(bases).map(|p| p.y + p.y).collect();

        ark_ff::batch_inversion(&mut denoms);

        ark_std::cfg_iter!(bases)
            .zip(denoms)
            .map(|(p, _2y_inv)| {
                let (x, y) = p.xy().unwrap();
                let t =
                    _2y_inv * (x.square() * C::BaseField::from(3) + <C as SWCurveConfig>::COEFF_A); // (3x^2 + a) / 2y
                let x_n = t.square() - x - x;
                let y_n = t * (x - x_n) - y;
                Affine::<C>::new_unchecked(x_n, y_n)
            })
            .collect()
    }

    fn batch_double_affine_in_place<C: GLVConfig>(bases: &mut [Affine<C>]) {
        let three = C::BaseField::from(3);
        let sw_a = <C as SWCurveConfig>::COEFF_A;
        let mut denoms: Vec<C::BaseField> = ark_std::cfg_iter!(bases).map(|p| p.y + p.y).collect();

        ark_ff::batch_inversion(&mut denoms);
        // ark_ff::batch_inversion_and_mul(&mut denoms, &C::BaseField::one());

        cfg_iter_mut!(bases)
            .zip(ark_std::cfg_into_iter!(denoms))
            .for_each(|(p, _2y_inv)| {
                let t = _2y_inv * (p.x.square() * three + sw_a); // (3x^2 + a) / 2y
                let old_x = p.x;
                p.x = t.square() - p.x - p.x;
                p.y = t * (old_x - p.x) - p.y;
            })
    }

    fn batch_add_affine<C: GLVConfig>(
        bases1: Vec<Affine<C>>,
        bases2: Vec<Affine<C>>,
    ) -> Vec<Affine<C>> {
        let mut denoms: Vec<C::BaseField> = ark_std::cfg_iter!(bases1)
            .zip(ark_std::cfg_iter!(bases2))
            .map(|(p1, p2)| p2.x - p1.x)
            .collect();

        ark_ff::batch_inversion(&mut denoms);

        ark_std::cfg_iter!(bases1)
            .zip(ark_std::cfg_iter!(bases2))
            .zip(ark_std::cfg_iter!(denoms))
            .map(|((p1, p2), _x2_m_x1)| {
                let (x1, y1) = p1.xy().unwrap();
                let (x2, y2) = p2.xy().unwrap();
                let t = (y2 - y1) * _x2_m_x1;
                let x_n = t.square() - x1 - x2;
                let y_n = t * (x1 - x_n) - y1;
                Affine::<C>::new_unchecked(x_n, y_n)
            })
            .collect()
    }

    fn batch_mul_by_x_affine<C: GLVConfig>(
        bases: Vec<Affine<C>>,
        x: C::ScalarField,
    ) -> Vec<Affine<C>> {
        let mut res: Vec<Affine<C>> = bases.clone();
        for b in ark_ff::BitIteratorBE::without_leading_zeros(x.into_bigint()).skip(1) {
            batch_double_affine_in_place(&mut res);
            if b {
                res = batch_add_affine(res, bases.clone());
            }
        }
        res
    }

    #[test]
    fn bench_folding() {
        let rng = &mut test_rng();
        let log_n = 10;
        _bench_folding(log_n);

        let n = 2usize.pow(log_n);
        let bases: Vec<_> = (0..n).map(|_| ark_pallas::Affine::rand(rng)).collect();
        let x = ark_pallas::Fr::rand(rng);
        let dbl: Vec<_> = bases
            .iter()
            .map(|p| {
                let mut p = p.into_group();
                p.double_in_place();
                p.into_affine()
            })
            .collect();
        assert_eq!(dbl, batch_double_affine(bases.clone()));

        let bases2: Vec<_> = (0..n).map(|_| ark_pallas::Affine::rand(rng)).collect();
        let bases1 = bases.clone();
        let add: Vec<_> = bases
            .into_iter()
            .zip(bases2.iter())
            .map(|(p1, p2)| p1 + p2)
            .collect();
        assert_eq!(add, batch_add_affine(bases1.clone(), bases2.clone()));

        let _timer = start_timer!(|| format!("Batch affine folding, log(n) = {log_n}"));
        let x_bases2 = batch_mul_by_x_affine(bases2.clone(), x);
        let res = batch_add_affine(bases1.clone(), x_bases2);
        end_timer!(_timer);

        let _timer = start_timer!(|| format!("Naive folding, log(n) = {log_n}"));
        let res_: Vec<ark_pallas::Projective> = ark_std::cfg_into_iter!(bases1)
            .zip(ark_std::cfg_into_iter!(bases2))
            .map(|(l, r)| l + r * x)
            .collect();
        let _to_affine = start_timer!(|| "batch affine conversion");
        let res_ = ark_pallas::Projective::normalize_batch(&res_);
        end_timer!(_to_affine);
        end_timer!(_timer);

        assert_eq!(res_, res);
    }
}
