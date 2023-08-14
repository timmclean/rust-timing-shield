use crate::{TpBool, TpEq, TpI16, TpI32, TpI64, TpI8, TpU16, TpU32, TpU64, TpU8};

/// A trait for performing comparisons on types with timing leak protection.
///
/// **Important**: implementations of this trait are only required to protect inputs that are already a
/// timing-protected type. For example, `a.tp_lt(&b)` is allowed to leak `a` if `a` is a `u32`,
/// instead of a timing-protected type like `TpU32`.
///
/// Ideally, this trait will be removed in the future if/when Rust allows overloading of the `<`,
/// `>`, `<=`, and `>=` operators.
pub trait TpOrd<Rhs = Self>: TpEq<Rhs>
where
    Rhs: ?Sized,
{
    /// Compute `self < other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_lt(&self, other: &Rhs) -> TpBool;

    /// Compute `self > other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_gt(&self, other: &Rhs) -> TpBool;

    /// Compute `self <= other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_lt_eq(&self, other: &Rhs) -> TpBool {
        !self.tp_gt(other)
    }

    /// Compute `self >= other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_gt_eq(&self, other: &Rhs) -> TpBool {
        !self.tp_lt(other)
    }
}

macro_rules! impl_tp_ord {
    (
        $lhs_type:ty, $rhs_type:ty,
        tp_lt($lhs_var:ident, $rhs_var:ident) => $lt_expr:expr
    ) => {
        impl TpOrd<$rhs_type> for $lhs_type {
            #[inline(always)]
            fn tp_lt(&self, other: &$rhs_type) -> TpBool {
                let $lhs_var = self;
                let $rhs_var = other;
                $lt_expr
            }

            #[inline(always)]
            fn tp_gt(&self, other: &$rhs_type) -> TpBool {
                other.tp_lt(self)
            }
        }
    };
}

macro_rules! impl_tp_ord_for_number {
    (
        $tp_type:ident,
        $type:ident,
        tp_lt: ($tp_lt_lhs_var:ident, $tp_lt_rhs_var:ident) => $tp_lt_expr:expr
    ) => {
        impl_tp_ord!($tp_type, $tp_type, tp_lt(l, r) => {
            let $tp_lt_lhs_var = l.expose();
            let $tp_lt_rhs_var = r.expose();
            $tp_lt_expr
        });
        impl_tp_ord!($type, $tp_type, tp_lt(l, r) => {
            let $tp_lt_lhs_var = *l;
            let $tp_lt_rhs_var = r.expose();
            $tp_lt_expr
        });
        impl_tp_ord!($tp_type, $type, tp_lt(l, r) => {
            let $tp_lt_lhs_var = l.expose();
            let $tp_lt_rhs_var = *r;
            $tp_lt_expr
        });
    }
}

impl_tp_ord_for_number!(TpU8, u8, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u32).wrapping_sub(rhs as u32);
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 31) as u8) }
});

impl_tp_ord_for_number!(TpU16, u16, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u32).wrapping_sub(rhs as u32);
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 31) as u8) }
});

impl_tp_ord_for_number!(TpU32, u32, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u64).wrapping_sub(rhs as u64);
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 63) as u8) }
});

impl_tp_ord_for_number!(TpU64, u64, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u128).wrapping_sub(rhs as u128);
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 127) as u8) }
});

impl_tp_ord_for_number!(TpI8, i8, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i32).wrapping_sub(rhs as i32)) as u32;
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 31) as u8) }
});

impl_tp_ord_for_number!(TpI16, i16, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i32).wrapping_sub(rhs as i32)) as u32;
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 31) as u8) }
});

impl_tp_ord_for_number!(TpI32, i32, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i64).wrapping_sub(rhs as i64)) as u64;
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 63) as u8) }
});

impl_tp_ord_for_number!(TpI64, i64, tp_lt: (lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i128).wrapping_sub(rhs as i128)) as u128;
    unsafe { TpBool::from_u8_unchecked((overflowing_iff_lt >> 127) as u8) }
});
