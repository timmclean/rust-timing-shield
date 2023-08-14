use crate::{TpBool, TpI16, TpI32, TpI64, TpI8, TpU16, TpU32, TpU64, TpU8};

/// A trait for performing conditional swaps of two values without leaking whether the swap
/// occurred.
///
/// For convenience, you may want to use the [`select`](struct.TpBool.html#method.select) or
/// [`cond_swap`](struct.TpBool.html#method.cond_swap) methods on [`TpBool`](struct.TpBool.html)
/// instead of using this trait directly:
///
/// ```
/// # use timing_shield::*;
/// let condition: TpBool;
/// let mut a: TpU32;
/// let mut b: TpU32;
/// # condition = TpBool::protect(true);
/// # a = TpU32::protect(5);
/// # b = TpU32::protect(6);
/// // ...
/// condition.cond_swap(&mut a, &mut b);
///
/// // OR:
/// let a_if_true = condition.select(a, b);
/// # assert_eq!(a_if_true.expose(), a.expose());
/// ```
///
/// This trait doesn't really make sense to implement on non-`Tp` types.
pub trait TpCondSwap {
    /// Swap `a` and `b` if and only if `condition` is true.
    ///
    /// Implementers of this trait must take care to avoid leaking whether the swap occurred.
    fn tp_cond_swap(condition: TpBool, a: &mut Self, b: &mut Self);

    /// Returns one of the arguments, depending on the value of `condition`.
    /// The return value is selected without branching on the boolean value, and no information
    /// about which value was selected will be leaked.
    ///
    /// Implementers of this trait must take care to avoid leaking the value of `condition`.
    ///
    /// See also [`TpBool::select`] for a more ergonomic way to use this function.
    #[inline(always)]
    fn select(condition: TpBool, when_true: Self, when_false: Self) -> Self
    where
        Self: Sized,
    {
        let mut result = when_false;
        let mut replace_with = when_true;
        Self::tp_cond_swap(condition, &mut result, &mut replace_with);
        result
    }
}

impl<T> TpCondSwap for [T]
where
    T: TpCondSwap,
{
    #[inline(always)]
    fn tp_cond_swap(condition: TpBool, a: &mut Self, b: &mut Self) {
        if a.len() != b.len() {
            panic!("cannot swap values of slices of unequal length");
        }

        for (a_elem, b_elem) in a.iter_mut().zip(b.iter_mut()) {
            condition.cond_swap(a_elem, b_elem);
        }
    }
}

impl<T> TpCondSwap for Vec<T>
where
    T: TpCondSwap,
{
    #[inline(always)]
    fn tp_cond_swap(condition: TpBool, a: &mut Self, b: &mut Self) {
        condition.cond_swap(a.as_mut_slice(), b.as_mut_slice());
    }
}

impl TpCondSwap for TpBool {
    #[inline(always)]
    fn tp_cond_swap(condition: TpBool, a: &mut TpBool, b: &mut TpBool) {
        let swapper = (*a ^ *b) & condition;
        *a ^= swapper;
        *b ^= swapper;
    }
}

macro_rules! impl_tp_cond_swap_for_number {
    ($tp_type:ident, $type:ident) => {
        impl TpCondSwap for $tp_type {
            #[inline(always)]
            fn tp_cond_swap(condition: TpBool, a: &mut $tp_type, b: &mut $tp_type) {
                // Zero-extend condition to this type's width
                let cond_zx = $tp_type::protect(condition.expose_u8_unprotected() as $type);

                // Create mask of 11...11 for true or 00...00 for false
                let mask = !(cond_zx - 1);

                // swapper will be a XOR b for true or 00...00 for false
                let swapper = (*a ^ *b) & mask;

                *a ^= swapper;
                *b ^= swapper;
            }
        }
    };
}

impl_tp_cond_swap_for_number!(TpU8, u8);
impl_tp_cond_swap_for_number!(TpU16, u16);
impl_tp_cond_swap_for_number!(TpU32, u32);
impl_tp_cond_swap_for_number!(TpU64, u64);
impl_tp_cond_swap_for_number!(TpI8, i8);
impl_tp_cond_swap_for_number!(TpI16, i16);
impl_tp_cond_swap_for_number!(TpI32, i32);
impl_tp_cond_swap_for_number!(TpI64, i64);
