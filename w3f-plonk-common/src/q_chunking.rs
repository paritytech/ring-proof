use ark_ff::{Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use w3f_pcs::pcs::Commitment;
use w3f_pcs::utils;

fn chunk_quotient<F: Field>(q: DensePolynomial<F>, n: usize) -> Vec<DensePolynomial<F>> {
    q.coeffs
        .chunks(n)
        .map(|coeffs| DensePolynomial::from_coefficients_slice(coeffs))
        .collect()
}

fn fold_quotient_chunks<F: Field>(chunks: &[DensePolynomial<F>], z_to_n: F) -> DensePolynomial<F> {
    chunks
        .iter()
        .zip(utils::powers(z_to_n))
        .map(|(chunk, coeff)| chunk * coeff)
        .reduce(|acc, new| acc + new)
        .unwrap()
}

fn quotient_commitment<F: PrimeField, C: Commitment<F>>(chunks: &[C], z_to_n: F) -> C {
    chunks
        .iter()
        .zip(utils::powers(z_to_n))
        .map(|(chunk, coeff)| chunk.mul(coeff))
        .sum()
}

#[cfg(test)]
mod tests {}
