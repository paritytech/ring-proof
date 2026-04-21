use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use w3f_pcs::pcs::ipa::ipa_pc;
use w3f_pcs::pcs::ipa;
use w3f_pcs::pcs::kzg::commitment::WrappedAffine;
use w3f_pcs::pcs::PCS;
use w3f_pcs::Poly;

// To open a hiding commitment `Cp = Commit(p, t1) = (p0.G0 + ... + pn.Gn) + t1.H` at `z`,
// the prover:
// 1. Computes a hiding commitment to a random `q` such that `deg(q) = deg(p)` and `q(z) = 0`
//   `Cq = Commit(q, t2) = (q0.G0 + ... + qn.Gn) + t2.H`.
// 2. Computes the blinded polynomial `p' = p + a.q`, p'(z) = p(z) + a.q(z) = p(z)`.
// 3. Opens the non-hiding commitment `Cp' = Commit(p', 0)` to the blinded polynomial `p'`.
// 4. Reveals `Cq` and `t = t1 + a.t2` to the verifier.
// The verifier
// 1. Computes the non-hiding commitment `Cp'` as `Cp + a.Cq - t'H = (Cp - t1.H) + a.(Cq - t2.H)`.
// 2. Verifies the opening against `Cp'`.
pub struct HidingIpa<C: CurveGroup> {
    ipa_pcs: ipa::IPA<C>,
    h: C::Affine,
}

/// `Cp = Commit(p, t1) = (p0.G0 + ... + pn.Gn) + t1.H`.
pub struct HidingProof<C: CurveGroup> {
    /// A hiding commitment to the blinding polynomial `q`, `deg(q) = deg(p), q(z) = 0`.
    /// `Commit(q, t2) = (q0.G0 + ... + qn.Gn) + t2.H`.
    q: C::Affine,
    /// The blinding factor `t` in the hiding commitment `Cp' = Cp + a.Cq` to the blinded polynomial `p' = p + a.q`.
    /// `t = t1 + a.t2`, `Cp' = Commit(p', t) = Commit(p', 0) + (t1 + a.t2).H`
    t: C::ScalarField,
    /// Opening proof for the non-hiding commitment `Commit(p', 0)` to `p'`.
    ipa_pcs_proof: ipa_pc::Proof<C::Affine>,
    // TODO: remove
    a: C::ScalarField,
}

impl<F: PrimeField, C: CurveGroup<ScalarField=F>> HidingIpa<C> {
    fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Self {
        let ipa_pcs = ipa::IPA::setup(max_degree, rng);
        let h = C::Affine::rand(rng);
        Self {
            ipa_pcs,
            h,
        }
    }

    fn commit(&self, p: &Poly<F>, t: F) -> Result<WrappedAffine<C::Affine>, ()> {
        let c = ipa::IPA::commit(&self.ipa_pcs, p)?;
        let c = c.0 + self.h * t;
        let c = c.into_affine();
        Ok(WrappedAffine(c))
    }

    fn open<R: Rng>(&self, p: &Poly<F>, z: F, t: F, rng: &mut R) -> Result<HidingProof<C>, ()> {
        let t1 = t;
        let mut q = Poly::rand(p.degree(), rng);
        let q_at_z = q.evaluate(&z);
        q[0] -= q_at_z;
        debug_assert!(q.evaluate(&z).is_zero());
        let t2 = F::rand(rng);
        let cq = self.commit(&q, t2)?.0;
        let a = F::rand(rng); // TODO: that's a FS point
        let p = p + q * a;
        let t = t1 + t2 * a;
        let ipa_pcs_proof = ipa::IPA::open(&self.ipa_pcs, &p, z)?;
        Ok(HidingProof{
            q: cq,
            t,
            ipa_pcs_proof,
            a
        })
    }

    fn verify(&self, p: C::Affine, z: F, v: F, proof: HidingProof<C>) -> Result<(), ()> {
        let p = p + proof.q * proof.a - self.h * proof.t;
        ipa::IPA::verify(&self.ipa_pcs, WrappedAffine(p.into_affine()), z, v, proof.ipa_pcs_proof)
    }
}


#[cfg(test)]
mod tests {
    use ark_ff::Zero;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use ark_std::{test_rng, UniformRand};
    use w3f_pcs::Poly;
    use crate::ipa_hiding::HidingIpa;

    #[test]
    fn test_hiding_ipa_opening() {
        let rng = &mut test_rng();

        let max_coeffs = 2usize.pow(6);
        let max_degree = max_coeffs - 1;

        let hiding_pcs = HidingIpa::<ark_pallas::Projective>::setup(max_coeffs - 1, rng);

        let p = Poly::rand(max_degree, rng);
        let t = ark_pallas::Fr::rand(rng);

        let c = hiding_pcs.commit(&p, t).unwrap().0;

        let z = ark_pallas::Fr::rand(rng);
        let v = p.evaluate(&z);
        let pi = hiding_pcs.open(&p, z, t, rng).unwrap();

        assert!(hiding_pcs.verify(c, z, v, pi).is_ok());
    }
}