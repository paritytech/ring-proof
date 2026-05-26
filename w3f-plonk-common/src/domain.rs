use crate::FieldColumn;
use ark_ff::{batch_inversion, FftField, Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial,
};
use ark_std::{vec, vec::Vec};
use getrandom_or_panic::getrandom_or_panic;

pub const ZK_ROWS: usize = 3;

// Domains for performing calculations with constraint polynomials of degree up to 4.
#[derive(Clone)]
pub struct Domains<F: FftField> {
    pub x1: GeneralEvaluationDomain<F>,
    pub x4: GeneralEvaluationDomain<F>,
}

impl<F: FftField> Domains<F> {
    fn new(n: usize) -> Self {
        let x1 = GeneralEvaluationDomain::<F>::new(n)
            .unwrap_or_else(|| panic!("No domain of size {}", n));
        let x4 = GeneralEvaluationDomain::<F>::new(4 * n)
            .unwrap_or_else(|| panic!("No domain of size {}", 4 * n));
        Self { x1, x4 }
    }

    pub fn column_from_evals(&self, padded_evals: Vec<F>, payload_len: usize) -> FieldColumn<F> {
        debug_assert_eq!(padded_evals.len(), self.x1.size());
        let evals = Evaluations::from_vec_and_domain(padded_evals, self.x1);
        let poly = evals.interpolate_by_ref();
        let evals_4x = poly.evaluate_over_domain_by_ref(self.x4);
        FieldColumn {
            poly,
            evals,
            evals_4x,
            payload_len,
        }
    }

    fn column_from_poly(&self, poly: DensePolynomial<F>) -> FieldColumn<F> {
        debug_assert!(poly.degree() + 1 <= self.x1.size());
        let evals_4x = self.amplify(&poly);
        let evals = evals_4x.evals.iter().step_by(4).cloned().collect();
        let evals = Evaluations::from_vec_and_domain(evals, self.x1);
        FieldColumn {
            poly,
            evals,
            evals_4x,
            payload_len: self.x1.size(),
        }
    }

    // Amplifies the number of the evaluations of the polynomial so it can be multiplied in linear time.
    fn amplify(&self, poly: &DensePolynomial<F>) -> Evaluations<F> {
        poly.evaluate_over_domain_by_ref(self.x4)
    }
}

#[derive(Clone)]
pub struct Domain<F: FftField> {
    pub domains: Domains<F>,
    pub zk_rows: usize,
    pub capacity: usize,
    pub not_last_row: FieldColumn<F>,
    pub l_first: FieldColumn<F>,
    pub l_last: FieldColumn<F>,
    zk_rows_prod: DensePolynomial<F>,
}

impl<F: FftField> Domain<F> {
    pub fn new(n: usize, hiding: bool) -> Self {
        if hiding {
            Self::with_zk_rows(n, ZK_ROWS)
        } else {
            Self::with_zk_rows(n, 0)
        }
    }

    pub fn with_zk_rows(n: usize, zk_rows: usize) -> Self {
        let domains = Domains::new(n);
        let domain_size = domains.x1.size();
        let capacity = domain_size - zk_rows;
        let last_row_index = capacity - 1;

        let l_first = l_i(0, domain_size);
        let l_first = domains.column_from_evals(l_first, 0);
        let l_last = l_i(last_row_index, domain_size);
        let l_last = domains.column_from_evals(l_last, 0);

        let (zk_rows_prod, last_row) = compute_row_polys(domains.x1, zk_rows).unwrap();
        let not_last_row = domains.column_from_poly(last_row);

        Self {
            domains,
            zk_rows,
            capacity,
            not_last_row,
            l_first,
            l_last,
            zk_rows_prod,
        }
    }

    pub fn is_hiding(&self) -> bool {
        self.zk_rows != 0
    }

    pub fn compute_quotient(&self, poly: &DensePolynomial<F>) -> Option<DensePolynomial<F>> {
        let (q, r) = self.div_by_z_with_remainder(poly);
        r.is_zero().then_some(q)
    }

    fn div_by_z_with_remainder(
        &self,
        p: &DensePolynomial<F>,
    ) -> (DensePolynomial<F>, DensePolynomial<F>) {
        let dividend = if self.is_hiding() {
            &(p * &self.zk_rows_prod)
        } else {
            p
        };
        dividend.divide_by_vanishing_poly(self.domains.x1)
    }

    fn _column(&self, mut values: Vec<F>, public: bool) -> FieldColumn<F> {
        let payload_len = values.len();
        assert!(payload_len <= self.capacity);
        let no_blinding = !self.is_hiding() || public || cfg!(feature = "test-vectors");
        if no_blinding {
            values.resize(self.domain_size(), F::zero());
        } else {
            values.resize(self.capacity, F::zero());
            let rng = &mut getrandom_or_panic();
            values.resize_with(self.domain_size(), || F::rand(rng));
        }
        self.domains.column_from_evals(values, payload_len)
    }

    pub fn column(&self, values: Vec<F>) -> FieldColumn<F> {
        self._column(values, false)
    }

    pub fn public_column(&self, values: Vec<F>) -> FieldColumn<F> {
        self._column(values, true)
    }

    pub fn domain(&self) -> GeneralEvaluationDomain<F> {
        self.domains.x1
    }

    pub fn domain_size(&self) -> usize {
        self.domain().size()
    }

    pub fn omega(&self) -> F {
        self.domain().group_gen()
    }

    pub fn evaluate(&self, zeta: F) -> EvaluatedDomain<F> {
        EvaluatedDomain::new(self.domain(), zeta, self.zk_rows)
    }
}

fn l_i<F: FftField>(i: usize, n: usize) -> Vec<F> {
    let mut l_i = vec![F::zero(); n];
    l_i[i] = F::one();
    l_i
}

/// For the generator `w = domain.group_gen()` of a domain of size `N`, returns `w^{N-1}, w^{N-2}, ..., w^0 = 1`.
fn elements_rev<F: FftField, D: EvaluationDomain<F>>(domain: D) -> impl Iterator<Item = F> {
    let w_inv = domain.group_gen_inv();
    debug_assert_eq!(w_inv * domain.group_gen(), F::one()); // w^{n-1} = w^{-1}
    ark_std::iter::successors(Some(w_inv), move |wi| (!wi.is_one()).then(|| w_inv * wi))
}

/// `Z(c) = X - c`
fn z<F: Field>(c: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(vec![-c, F::one()])
}

fn one<F: Field>() -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(vec![F::one()])
}

/// For a domain of size `N`, returns `(Z(X), (X - w^{N - zk_rows - 1}))`,
/// where `Z(X) = (X - w^{N-1}) * (X - w^{N-2}) * ... * (X - w^{N - zk_rows})`.
fn compute_row_polys<F: FftField, D: EvaluationDomain<F>>(
    domain: D,
    zk_rows: usize,
) -> Option<(DensePolynomial<F>, DensePolynomial<F>)> {
    if domain.size() < zk_rows + 1 {
        return None;
    }
    let mut wis = elements_rev(domain).map(|wi| z(wi));
    let zk_rows_prod = wis.by_ref().take(zk_rows).fold(one(), |acc, x| acc * x);
    let last_row = wis.by_ref().next().unwrap();
    Some((zk_rows_prod, last_row))
}

pub struct EvaluatedDomain<F: FftField> {
    pub domain: GeneralEvaluationDomain<F>,
    pub not_last_row: F,
    pub l_first: F,
    pub l_last: F,
    pub vanishing_polynomial_inv: F,
}

impl<F: FftField> EvaluatedDomain<F> {
    pub fn new(domain: GeneralEvaluationDomain<F>, z: F, zk_rows: usize) -> Self {
        let mut z_n = z; // z^n, n=2^d - domain size, so squarings only
        for _ in 0..domain.log_size_of_group() {
            z_n.square_in_place();
        }
        let z_n_minus_one = z_n - F::one(); // vanishing polynomial of the full domain

        // w^{n-1}
        let mut wi = domain.group_gen_inv();
        // Vanishing polynomial of zk rows: prod = (z - w^{n-1})...(z - w^{n-k})
        let mut prod = F::one();
        for _ in 0..zk_rows {
            prod *= z - wi;
            wi *= domain.group_gen_inv();
        }
        // z - w^{n-(k+1)}}
        let not_last_row = z - wi;

        // w^{k+1}
        let wj = domain.group_gen().pow([(zk_rows + 1) as u64]);

        let mut inv = [z_n_minus_one, z - F::one(), wj * z - F::one()];
        batch_inversion(&mut inv);

        let vanishing_polynomial_inv = prod * inv[0];
        let z_n_minus_one_div_n = z_n_minus_one * domain.size_inv();
        let l_first = z_n_minus_one_div_n * inv[1];
        let l_last = z_n_minus_one_div_n * inv[2];

        Self {
            domain,
            not_last_row,
            l_first,
            l_last,
            vanishing_polynomial_inv,
        }
    }

    pub(crate) fn divide_by_vanishing_poly_in_zeta(&self, poly_in_zeta: F) -> F {
        poly_in_zeta * self.vanishing_polynomial_inv
    }

    pub fn omega(&self) -> F {
        self.domain.group_gen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381_bandersnatch::Fq;
    use ark_ff::One;
    use ark_poly::Radix2EvaluationDomain;
    use ark_std::{test_rng, UniformRand};

    fn _test_evaluated_domain(hiding: bool) {
        let rng = &mut test_rng();

        // let domain = GeneralEvaluationDomain::new(1024);
        let n = 1024;
        let domain = Domain::new(n, hiding);
        let z = Fq::rand(rng);
        let domain_eval = domain.evaluate(z);
        assert_eq!(domain.l_first.poly.evaluate(&z), domain_eval.l_first);
        assert_eq!(domain.l_last.poly.evaluate(&z), domain_eval.l_last);
        assert_eq!(
            domain.not_last_row.poly.evaluate(&z),
            domain_eval.not_last_row
        );
    }

    #[test]
    fn test_domain_zk_rows() {
        let log_n = 4;
        let n = 1 << log_n;
        let domain = Radix2EvaluationDomain::<Fq>::new(n).unwrap();
        let w = domain.group_gen();
        let (zk_rows_prod, last_row) = compute_row_polys(domain, 0).unwrap();
        assert_eq!(zk_rows_prod, one());
        assert_eq!(last_row, z(domain.group_gen_inv()));

        let zk_rows = 3;
        let (zk_rows_prod, last_row) = compute_row_polys(domain, zk_rows).unwrap();
        assert_eq!(zk_rows_prod.degree(), zk_rows);
        let last_row_index = n - (zk_rows + 1);
        assert_eq!(last_row, z(w.pow([last_row_index as u64])));

        let zk_rows = n - 1;
        let (zk_rows_prod, last_row) = compute_row_polys(domain, zk_rows).unwrap();
        assert_eq!(last_row, z(Fq::one()));
        assert_eq!(
            zk_rows_prod * last_row,
            domain.vanishing_polynomial().into()
        );

        let zk_rows = n;
        assert!(compute_row_polys(domain, zk_rows).is_none());
    }

    #[test]
    fn test_evaluated_domain() {
        _test_evaluated_domain(false);
        _test_evaluated_domain(true);
    }
}
