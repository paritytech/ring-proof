//! Branch-free handling of secret witness bits (the prover's ring position
//! and the blinding scalar bits). These helpers keep secret-dependent
//! branches and memory indexing out of witness generation. They are defense
//! in depth, not a complete side-channel countermeasure: later pipeline
//! stages (in particular the polynomial commitment MSMs) still process the
//! witness in variable time.

use ark_ec::short_weierstrass::{Projective as SwProjective, SWCurveConfig};
use ark_ec::twisted_edwards::{Projective as TeProjective, TECurveConfig};
use ark_ff::Field;

/// Lifts a bit to a field element without branching on its value.
///
/// `F::from(bool)` bottoms out in arkworks' `from_bigint`, which returns
/// early for zero; mapping the bit to 1 or 2 first routes both values
/// through the same Montgomery conversion.
pub fn bit_to_field<F: Field>(bit: bool) -> F {
    F::from(bit as u64 + 1) - F::one()
}

/// Arithmetic two-way select. `mask` must be 0 or 1.
pub fn field_select<F: Field>(mask: F, if_true: F, if_false: F) -> F {
    if_false + mask * (if_true - if_false)
}

/// Coordinate-wise arithmetic select between two curve points.
pub trait PointSelect<F: Field>: Sized {
    /// `mask` must be 0 or 1.
    fn select(mask: F, if_true: &Self, if_false: &Self) -> Self;
}

impl<C: TECurveConfig> PointSelect<C::BaseField> for TeProjective<C> {
    fn select(mask: C::BaseField, if_true: &Self, if_false: &Self) -> Self {
        Self::new_unchecked(
            field_select(mask, if_true.x, if_false.x),
            field_select(mask, if_true.y, if_false.y),
            field_select(mask, if_true.t, if_false.t),
            field_select(mask, if_true.z, if_false.z),
        )
    }
}

impl<C: SWCurveConfig> PointSelect<C::BaseField> for SwProjective<C> {
    fn select(mask: C::BaseField, if_true: &Self, if_false: &Self) -> Self {
        Self::new_unchecked(
            field_select(mask, if_true.x, if_false.x),
            field_select(mask, if_true.y, if_false.y),
            field_select(mask, if_true.z, if_false.z),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381_bandersnatch::Fq;

    #[test]
    fn bit_lift_is_exact() {
        assert_eq!(bit_to_field::<Fq>(false), Fq::from(0));
        assert_eq!(bit_to_field::<Fq>(true), Fq::from(1));
    }
}
