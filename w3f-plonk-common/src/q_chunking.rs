use ark_ff::{Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use w3f_pcs::pcs::Commitment;
use w3f_pcs::utils;

/// The last chunk takes all the remaining coefficients,
/// so `q = q_0 + X^n.q_1 + ... + X^{(Q-1)n}.q_{Q-1}` holds for any `Q`.
pub fn chunk_quotient<F: Field, const Q: usize>(
    q: DensePolynomial<F>,
    n: usize,
) -> [DensePolynomial<F>; Q] {
    let len = q.coeffs.len();
    core::array::from_fn(|i| {
        let start = (i * n).min(len);
        let end = if i == Q - 1 {
            len
        } else {
            (start + n).min(len)
        };
        DensePolynomial::from_coefficients_slice(&q.coeffs[start..end])
    })
}

pub fn chunk_coeffs<F: Field>(z_to_n: F) -> impl Iterator<Item = F> {
    utils::powers(z_to_n)
}

pub fn fold_quotient_chunks<F: Field>(
    chunks: &[DensePolynomial<F>],
    z_to_n: F,
) -> DensePolynomial<F> {
    chunks
        .iter()
        .zip(chunk_coeffs(z_to_n))
        .map(|(chunk, coeff)| chunk * coeff)
        .reduce(|acc, new| acc + new)
        .unwrap()
}

pub fn compose_quotient<F: PrimeField, C: Commitment<F>>(chunks: &[C], z_to_n: F) -> C {
    chunks
        .iter()
        .zip(chunk_coeffs(z_to_n))
        .map(|(chunk, coeff)| chunk.mul(coeff))
        .sum()
}

#[cfg(test)]
mod tests {}
