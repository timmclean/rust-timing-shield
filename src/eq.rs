use std::ops::BitXor;
use std::ops::Not;

use crate::util::as_unsigned_type;
use crate::{TpBool, TpI16, TpI32, TpI64, TpI8, TpU16, TpU32, TpU64, TpU8, TP_FALSE, TP_TRUE};

/// A trait for performing equality tests on types with timing leak protection.
///
/// **Important**: implementations of this trait are only required to protect inputs that are already a
/// timing-protected type. For example, `a.tp_eq(&b)` is allowed to leak `a` if `a` is a `u32`,
/// instead of a timing-protected type like `TpU32`.
///
/// Ideally, this trait will be removed in the future if/when Rust allows overloading of the `==`
/// and `!=` operators.
pub trait TpEq<Rhs = Self>
where
    Rhs: ?Sized,
{
    /// Compare `self` with `other` for equality without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    ///
    /// Equivalent to `!a.tp_not_eq(&other)`
    fn tp_eq(&self, other: &Rhs) -> TpBool;

    /// Compare `self` with `other` for inequality without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    ///
    /// Equivalent to `!a.tp_eq(&other)`
    #[inline(always)]
    fn tp_not_eq(&self, other: &Rhs) -> TpBool {
        !self.tp_eq(other)
    }

    #[inline(always)]
    fn slice_eq(a: &[Self], b: &[Rhs]) -> TpBool
    where
        Self: Sized,
        Rhs: Sized,
    {
        if a.len() != b.len() {
            return TP_FALSE;
        }

        a.iter()
            .zip(b.iter())
            .fold(TP_TRUE, |prev, (a, b)| prev & a.tp_eq(b))
    }

    #[inline(always)]
    fn slice_not_eq(a: &[Self], b: &[Rhs]) -> TpBool
    where
        Self: Sized,
        Rhs: Sized,
    {
        if a.len() != b.len() {
            return TP_TRUE;
        }

        a.iter()
            .zip(b.iter())
            .fold(TP_FALSE, |prev, (a, b)| prev | a.tp_not_eq(b))
    }
}

impl<Lhs, Rhs> TpEq<[Rhs]> for [Lhs]
where
    Lhs: TpEq<Rhs>,
{
    #[inline(always)]
    fn tp_eq(&self, other: &[Rhs]) -> TpBool {
        Lhs::slice_eq(self, other)
    }

    #[inline(always)]
    fn tp_not_eq(&self, other: &[Rhs]) -> TpBool {
        Lhs::slice_not_eq(self, other)
    }
}

impl<Lhs, Rhs> TpEq<Vec<Rhs>> for Vec<Lhs>
where
    Lhs: TpEq<Rhs>,
{
    #[inline(always)]
    fn tp_eq(&self, other: &Vec<Rhs>) -> TpBool {
        Lhs::slice_eq(self, other)
    }

    #[inline(always)]
    fn tp_not_eq(&self, other: &Vec<Rhs>) -> TpBool {
        Lhs::slice_not_eq(self, other)
    }
}

impl<Lhs, Rhs, const N: usize> TpEq<[Rhs; N]> for [Lhs; N]
where
    Lhs: TpEq<Rhs>,
{
    #[inline(always)]
    fn tp_eq(&self, other: &[Rhs; N]) -> TpBool {
        Lhs::slice_eq(self, other)
    }

    #[inline(always)]
    fn tp_not_eq(&self, other: &[Rhs; N]) -> TpBool {
        Lhs::slice_not_eq(self, other)
    }
}

macro_rules! impl_tp_eq {
    (
        $lhs_type:ty, $rhs_type:ty,
        ($lhs_var:ident, $rhs_var:ident) => $eq_expr:expr,
        slice {
            fold_eq {
                initial: $eq_initial:expr,
                fold: ($eq_fold_acc:ident, $eq_fold_elem_left:ident, $eq_fold_elem_right:ident) => $eq_fold_expr:expr,
                final: ($eq_acc:ident) => $eq_final_expr:expr,
            }
            fold_not_eq {
                initial: $not_eq_initial:expr,
                fold: ($not_eq_fold_acc:ident, $not_eq_fold_elem_left:ident, $not_eq_fold_elem_right:ident) => $not_eq_fold_expr:expr,
                final: ($not_eq_acc:ident) => $not_eq_final_expr:expr,
            }
        }
    ) => {
        impl TpEq<$rhs_type> for $lhs_type {
            #[inline(always)]
            fn tp_eq(&self, other: &$rhs_type) -> TpBool {
                let $lhs_var = self;
                let $rhs_var = other;
                $eq_expr
            }

            #[inline(always)]
            fn slice_eq(a: &[Self], b: &[$rhs_type]) -> TpBool {
                if a.len() != b.len() {
                    return TP_FALSE;
                }

                let $eq_acc = a.iter().zip(b.iter()).fold(
                    $eq_initial,
                    |$eq_fold_acc, ($eq_fold_elem_left, $eq_fold_elem_right)| $eq_fold_expr,
                );
                $eq_final_expr
            }

            #[inline(always)]
            fn slice_not_eq(a: &[Self], b: &[$rhs_type]) -> TpBool {
                if a.len() != b.len() {
                    return TP_TRUE;
                }

                let $not_eq_acc = a.iter().zip(b.iter()).fold(
                    $not_eq_initial,
                    |$not_eq_fold_acc, ($not_eq_fold_elem_left, $not_eq_fold_elem_right)| {
                        $not_eq_fold_expr
                    },
                );
                $not_eq_final_expr
            }
        }
    };
}

macro_rules! impl_tp_eq_for_bool {
    (
        $lhs_type:ident,
        $rhs_type:ident,
        ($lhs_var:ident, $rhs_var:ident) => $eq_expr:expr
    ) => {
        impl_tp_eq!(
            $lhs_type,
            $rhs_type,
            ($lhs_var, $rhs_var) => $eq_expr,
            slice {
                fold_eq {
                    initial: TP_FALSE,
                    fold: (acc, a, b) => acc | (*a ^ *b),
                    final: (acc) => !acc,
                }
                fold_not_eq {
                    initial: TP_FALSE,
                    fold: (acc, a, b) => acc | (*a ^ *b),
                    final: (acc) => acc,
                }
            }
        );
    }
}

impl_tp_eq_for_bool!(
    TpBool, TpBool,
    (l, r) => l.bitxor(*r).not()
);
impl_tp_eq_for_bool!(
    bool, TpBool,
    (l, r) => unsafe { TpBool::from_u8_unchecked((*l as u8) ^ r.expose_u8_unprotected()).not() }
);
impl_tp_eq_for_bool!(
    TpBool, bool,
    (l, r) => unsafe { TpBool::from_u8_unchecked(l.expose_u8_unprotected() ^ (*r as u8)).not() }
);

macro_rules! impl_tp_eq_for_number {
    (
        $inner_type:ident,
        $tp_type:ident,
        ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
        ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr
    ) => {
        impl_tp_eq!(
            $lhs_type,
            $rhs_type,
            (lhs, rhs) => {
                let l = {
                    let $lhs_var = lhs;
                    $lhs_expr
                };
                let r = {
                    let $rhs_var = rhs;
                    $rhs_expr
                };
                let bit_diff = l ^ r;
                let msb_iff_zero_diff = bit_diff.wrapping_sub(1) & !bit_diff;
                let type_bitwidth = $inner_type::count_zeros(0);
                let unsigned_msb_iff_zero_diff = msb_iff_zero_diff as as_unsigned_type!($inner_type);
                let is_eq_u8 = (unsigned_msb_iff_zero_diff >> (type_bitwidth - 1)) as u8;
                unsafe { TpBool::from_u8_unchecked(is_eq_u8) }
            },
            slice {
                fold_eq {
                    initial: $tp_type::protect(0),
                    fold: (acc, a, b) => acc | (*a ^ *b),
                    final: (acc) => acc.tp_eq(&0),
                }
                fold_not_eq {
                    initial: $tp_type::protect(0),
                    fold: (acc, a, b) => acc | (*a ^ *b),
                    final: (acc) => acc.tp_not_eq(&0),
                }
            }
        );
    }
}

macro_rules! impl_all_tp_eq_for_number {
    ($type:ident, $tp_type:ident) => {
        impl_tp_eq_for_number!(
            $type, $tp_type,
            (l: $tp_type) => l.expose(),
            (r: $tp_type) => r.expose()
        );
        impl_tp_eq_for_number!(
            $type, $tp_type,
            (l: $type) => l,
            (r: $tp_type) => r.expose()
        );
        impl_tp_eq_for_number!(
            $type, $tp_type,
            (l: $tp_type) => l.expose(),
            (r: $type) => r
        );
    }
}

impl_all_tp_eq_for_number!(u8, TpU8);
impl_all_tp_eq_for_number!(u16, TpU16);
impl_all_tp_eq_for_number!(u32, TpU32);
impl_all_tp_eq_for_number!(u64, TpU64);
impl_all_tp_eq_for_number!(i8, TpI8);
impl_all_tp_eq_for_number!(i16, TpI16);
impl_all_tp_eq_for_number!(i32, TpI32);
impl_all_tp_eq_for_number!(i64, TpI64);
