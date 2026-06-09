use crate::auth_path::node::LevelWitnessWithBlinding;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use std::marker::PhantomData;
use w3f_pcs::aggregation::multiple::ShplonkTranscript;
use w3f_pcs::pcs::PCS;
use w3f_pcs::pcs::commitment::WrappedAffine;
use w3f_pcs::pcs::ipa::hiding::HidingIpa;
use w3f_pcs::shplonk::AggregateProof;
use w3f_plonk_common::piop::{ProverPiop, VerifierPiop};
use w3f_plonk_common::{ColumnsCommited, ColumnsEvaluated, FieldColumn};

pub mod auth_path;
pub mod circuit_fat;
pub mod circuit_tall;
// pub mod level;
pub mod prover;
pub mod verifier;

pub trait CurveModel: SWCurveConfig {}
impl<T> CurveModel for T where T: SWCurveConfig {}
type AffinePoint<C> = ark_ec::short_weierstrass::Affine<C>;
type ProjectivePoint<C> = ark_ec::short_weierstrass::Projective<C>;

// TODO: goes vto plonk-common in some form
/// A circuit over `C::ScalarField`.
pub trait CircuitParams<C: CurveGroup, G: CurveModel<BaseField = C::ScalarField>> {
    type Commitments: ColumnsCommited<C::ScalarField, WrappedAffine<C>>;
    type Evaluations: ColumnsEvaluated<C::ScalarField>;
    type ProverCircuit: ProverPiop<
            C::ScalarField,
            WrappedAffine<C>,
            Instance = AffinePoint<G>,
            Commitments = Self::Commitments,
            Evaluations = Self::Evaluations,
        >;
    type VerifierCircuit: VerifierPiop<C::ScalarField, WrappedAffine<C>>;

    fn prover_circuit(
        &self,
        level: LevelWitnessWithBlinding<AffinePoint<G>>,
    ) -> Self::ProverCircuit;

    fn verifier_circuit(
        &self,
        instance: (AffinePoint<G>, C::Affine),
        fixed_cols: &[WrappedAffine<C>],
        cols: Self::Commitments,
        evals: Self::Evaluations,
        zeta: C::ScalarField,
    ) -> Self::VerifierCircuit;

    fn fixed_columns(&self) -> Vec<FieldColumn<C::ScalarField>>;

    fn tree_nodes_column(
        &self,
        children_x_coords: &[C::ScalarField],
    ) -> FieldColumn<C::ScalarField>;

    fn max_children(&self) -> usize;

    #[cfg(test)] // an "application" runs usually a single circuit
    /// `h` is the pedersen blinding base (from the opposite side) to prove `C' = Ci + rH`
    fn setup(domain_size: usize, h: AffinePoint<G>, seed: AffinePoint<G>) -> Self;
}

pub struct CycleSideParams<
    C: CurveGroup,
    G: CurveModel<BaseField = C::ScalarField>,
    P: CircuitParams<C, G>,
> {
    pcs_params: HidingIpa<C>,
    piop_params: P,
    phantomm: PhantomData<G>,
}

pub struct CycleParams<
    C0: CurveModel,
    C1: CurveModel<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
    P0: CircuitParams<ProjectivePoint<C0>, C1>,
    P1: CircuitParams<ProjectivePoint<C1>, C0>,
> {
    c0_params: CycleSideParams<ProjectivePoint<C0>, C1, P0>,
    c1_params: CycleSideParams<ProjectivePoint<C1>, C0, P1>,
}

type LevelProof<C, G, P> = w3f_plonk_common::PiopProof<
    <C as PrimeGroup>::ScalarField,
    WrappedAffine<C>,
    <P as CircuitParams<C, G>>::Commitments,
    <P as CircuitParams<C, G>>::Evaluations,
>;

#[derive(Clone)]
pub struct CycleSideProof<
    C: CurveGroup,
    G: CurveModel<BaseField = C::ScalarField>,
    P: CircuitParams<C, G>,
> {
    piop_proofs: Vec<LevelProof<C, G, P>>,
    pcs_proof: AggregateProof<C::ScalarField, HidingIpa<C>>,
    todo: Coeffs<C::ScalarField>,
}

#[derive(Clone)]
pub struct CurveTreeProof<
    C0: CurveModel,
    C1: CurveModel<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
    P0: CircuitParams<ProjectivePoint<C0>, C1>,
    P1: CircuitParams<ProjectivePoint<C1>, C0>,
> {
    c0_proof: CycleSideProof<ProjectivePoint<C0>, C1, P0>,
    c1_proof: CycleSideProof<ProjectivePoint<C1>, C0, P1>,
}

impl<C: CurveGroup, G: CurveModel<BaseField = C::ScalarField>, P: CircuitParams<C, G>>
    CycleSideParams<C, G, P>
{
    pub fn commit_tree_nodes(
        &self,
        nodes_x_coords: &[C::ScalarField],
        bf: C::ScalarField,
    ) -> Result<WrappedAffine<C>, ()> {
        let nodes_column =
            <P as CircuitParams<C, G>>::tree_nodes_column(&self.piop_params, nodes_x_coords);
        let parent_node = self.pcs_params.commit_hiding(nodes_column.as_poly(), bf);
        parent_node
    }

    pub fn commit_fixed_columns(&self) -> Vec<WrappedAffine<C>> {
        let fixed_columns = <P as CircuitParams<C, G>>::fixed_columns(&self.piop_params);
        fixed_columns
            .iter()
            .map(|c| {
                self.pcs_params
                    .commit_hiding(c.as_poly(), C::ScalarField::zero())
                    .unwrap()
            })
            .collect()
    }
}

#[derive(Debug, PartialEq)]
pub enum CycleSide<C0, C1> {
    C0(C0),
    C1(C1),
}

#[derive(Clone)]
pub struct ArkTranscript(ark_transcript::Transcript);

impl<F: PrimeField, CS: PCS<F>> w3f_plonk_common::transcript::PlonkTranscript<F, CS>
    for ArkTranscript
{
    fn _128_bit_point(&mut self, label: &'static [u8]) -> F {
        self.0.challenge(label).read_reduce()
    }

    fn _add_serializable(&mut self, label: &'static [u8], message: &impl CanonicalSerialize) {
        self.0.label(label);
        self.0.append(message);
    }

    fn to_rng(mut self) -> impl RngCore {
        self.0.challenge(b"transcript_rng")
    }
}

impl ArkTranscript {
    pub fn new(label: &'static [u8]) -> Self {
        Self(ark_transcript::Transcript::new_labeled(label))
    }
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
    use crate::auth_path::node::LevelWitness;
    use crate::auth_path::path::AuthenticationPath;
    use crate::circuit_fat::params::PiopParams as CircuitParamsFat;
    use crate::circuit_tall::params::PiopParams as CircuitParamsTall;
    use ark_ec::AdditiveGroup;
    use ark_ec::scalar_mul::glv::GLVConfig;
    use ark_ec::scalar_mul::wnaf::WnafContext;
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, Field, Zero};
    use ark_ff::{FftField, PrimeField};
    use ark_pallas::PallasConfig;
    use ark_poly::DenseUVPolynomial;
    use ark_std::rand::Rng;
    use ark_std::{UniformRand, cfg_iter_mut, end_timer, start_timer, test_rng};
    use ark_vesta::VestaConfig;
    use num_format::{Locale, ToFormattedString};
    use w3f_pcs::Poly;
    use w3f_pcs::pcs::PCS;
    use w3f_pcs::pcs::PcsParams;
    use w3f_pcs::pcs::ipa::IPA;
    use w3f_plonk_common::test_helpers::random_vec;

    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    type PallasIPA = IPA<ark_pallas::Projective>;

    impl<C0, C1, P0, P1> CycleParams<C0, C1, P0, P1>
    where
        C0: CurveModel<BaseField: PrimeField>,
        C1: CurveModel<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
        P0: CircuitParams<ProjectivePoint<C0>, C1>,
        P1: CircuitParams<ProjectivePoint<C1>, C0>,
    {
        pub fn setup<R: Rng>(domain_size: usize, rng: &mut R) -> Self {
            let setup_degree = 3 * domain_size;
            let c0_pcs_params = HidingIpa::<ProjectivePoint<C0>>::setup(setup_degree, rng);
            let c1_pcs_params = HidingIpa::<ProjectivePoint<C1>>::setup(setup_degree, rng);
            let c0_piop_params =
                P0::setup(domain_size, c1_pcs_params.h, AffinePoint::<C1>::rand(rng));
            let c1_piop_params =
                P1::setup(domain_size, c0_pcs_params.h, AffinePoint::<C0>::rand(rng));
            Self {
                c0_params: CycleSideParams {
                    pcs_params: c0_pcs_params,
                    piop_params: c0_piop_params,
                    phantomm: PhantomData,
                },
                c1_params: CycleSideParams {
                    pcs_params: c1_pcs_params,
                    piop_params: c1_piop_params,
                    phantomm: PhantomData,
                },
            }
        }
    }

    #[test]
    fn test_circuit_tall() {
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsTall<ark_vesta::Affine>,
            CircuitParamsTall<ark_pallas::Affine>,
        >(9, 2);
    }

    #[test]
    fn test_circuit_fat() {
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsFat<ark_vesta::Affine>,
            CircuitParamsFat<ark_pallas::Affine>,
        >(8, 2);
    }

    // cargo test test_bench_curve_tree --release --features="print-trace" -- --show-output --ignored
    // cargo test test_bench_curve_tree --release --features="print-trace parallel" -- --show-output --ignored
    #[test]
    #[ignore]
    fn test_bench_curve_tree() {
        let (log_n, h) = (8, 2);
        println!("n = {}, height = {h}, FAT", 1 << log_n);
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsFat<ark_vesta::Affine>,
            CircuitParamsFat<ark_pallas::Affine>,
        >(log_n, h);
        println!();

        let (log_n, h) = (9, 2);
        println!("n = {}, height = {h}, TALL", 1 << log_n);
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsTall<ark_vesta::Affine>,
            CircuitParamsTall<ark_pallas::Affine>,
        >(log_n, h);
        println!();

        let (log_n, h) = (10, 2);
        println!("n = {}, height = {h}, TALL", 1 << log_n);
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsTall<ark_vesta::Affine>,
            CircuitParamsTall<ark_pallas::Affine>,
        >(log_n, h);
        println!();

        let (log_n, h) = (8, 4);
        println!("n = {}, height = {h}, FAT", 1 << log_n);
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsFat<ark_vesta::Affine>,
            CircuitParamsFat<ark_pallas::Affine>,
        >(log_n, h);
        println!();

        let (log_n, h) = (10, 4);
        println!("n = {}, height = {h}, TALL", 1 << log_n);
        _test_proof::<
            PallasConfig,
            VestaConfig,
            CircuitParamsTall<ark_vesta::Affine>,
            CircuitParamsTall<ark_pallas::Affine>,
        >(log_n, h);
        println!();
    }

    fn _test_proof<C0, C1, P0, P1>(log_n: usize, height: usize)
    where
        C0: CurveModel<BaseField: PrimeField>,
        C1: CurveModel<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
        P0: CircuitParams<ProjectivePoint<C0>, C1>,
        P1: CircuitParams<ProjectivePoint<C1>, C0>,
    {
        let rng = &mut test_rng();
        let domain_size = 1 << log_n;
        let params = CycleParams::<C0, C1, P0, P1>::setup(domain_size, rng);
        let (_leaf, path, wrapped_root) = random_path(&params, height, rng);
        let root = match wrapped_root {
            CycleSide::C0(root) => root, //TODO: panics on odd height
            _ => panic!(),
        };
        let max_nodes = params.c0_params.piop_params.max_children();
        println!(
            "capacity=**{}**, arity={max_nodes}",
            max_nodes
                .pow(height as u32)
                .to_formatted_string(&Locale::en)
        );
        let t_prove = start_timer!(|| format!(
            "Proving CurveTree membership, height={height}, domain={domain_size}, arity={max_nodes}, capacity={}",
            max_nodes.pow(height as u32)
        ));
        let (auth_path, proof) = params.prove(path, rng);
        end_timer!(t_prove);

        let t_verify = start_timer!(|| "Verifying CurveTree membership");
        let valid = params.verify(auth_path, proof, root);
        end_timer!(t_verify);
        assert!(valid);
    }

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

    pub fn random_nodes<
        C: CurveGroup,
        G: CurveModel<BaseField = C::ScalarField>,
        P: CircuitParams<C, G>,
        R: Rng,
    >(
        params: &CycleSideParams<C, G, P>,
        path_node: AffinePoint<G>,
        rng: &mut R,
    ) -> (C::Affine, LevelWitness<AffinePoint<G>>) {
        let level_witness = random_witness(params.piop_params.max_children(), path_node, rng);
        let parent = level_witness.compute_parent(params).unwrap();
        (parent, level_witness)
    }

    pub fn random_path<
        C0: CurveModel<BaseField: FftField>,
        C1: CurveModel<BaseField = C0::ScalarField, ScalarField = C0::BaseField>,
        P0: CircuitParams<ProjectivePoint<C0>, C1>,
        P1: CircuitParams<ProjectivePoint<C1>, C0>,
        R: Rng,
    >(
        params: &CycleParams<C0, C1, P0, P1>,
        length: usize,
        rng: &mut R,
    ) -> (
        AffinePoint<C0>,
        AuthenticationPath<ProjectivePoint<C0>, ProjectivePoint<C1>>,
        CycleSide<AffinePoint<C0>, AffinePoint<C1>>,
    ) {
        let c0_len = (length + 1) / 2;
        let c1_len = length / 2;
        debug_assert_eq!(c0_len + c1_len, length);
        let mut c0_path = Vec::with_capacity(c0_len);
        let mut c1_path = Vec::with_capacity(c1_len);

        let leaf = AffinePoint::<C0>::rand(rng);
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
