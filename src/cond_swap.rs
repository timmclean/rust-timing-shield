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
        // TODO a better way to select on slices

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

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    macro_rules! test_tp_cond_swap {
        ($test_name:ident, $tp_type:ident, $type:ident) => {
            mod $test_name {
                use super::*;

                fn protect_vec(v: &Vec<$type>) -> Vec<$tp_type> {
                    v.iter().map(|&elem| $tp_type::protect(elem)).collect()
                }

                fn expose_vec(v: &Vec<$tp_type>) -> Vec<$type> {
                    v.iter().map(|&elem| elem.expose()).collect()
                }

                quickcheck! {
                    fn swap(condition: bool, a: $type, b: $type) -> bool {
                        let mut a_tp = $tp_type::protect(a);
                        let mut b_tp = $tp_type::protect(b);

                        TpBool::protect(condition).cond_swap(&mut a_tp, &mut b_tp);

                        if condition {
                            (a_tp.expose() == b) && (b_tp.expose() == a)
                        } else {
                            (a_tp.expose() == a) && (b_tp.expose() == b)
                        }
                    }

                    fn swap_slices(condition: bool, a: Vec<$type>, b: Vec<$type>) -> quickcheck::TestResult {
                        let mut a_tp = protect_vec(&a);
                        let mut b_tp = protect_vec(&b);

                        if a.len() != b.len() {
                            return quickcheck::TestResult::must_fail(move || {
                                TpBool::protect(condition).cond_swap(a_tp.as_mut_slice(), b_tp.as_mut_slice());
                            });
                        }

                        TpBool::protect(condition).cond_swap(a_tp.as_mut_slice(), b_tp.as_mut_slice());

                        let a_after = expose_vec(&a_tp);
                        let b_after = expose_vec(&b_tp);

                        quickcheck::TestResult::from_bool(
                            if condition {
                                (a_after == b) && (b_after == a)
                            } else {
                                (a_after == a) && (b_after == b)
                            }
                        )
                    }

                    fn swap_vecs(condition: bool, a: Vec<$type>, b: Vec<$type>) -> quickcheck::TestResult {
                        let mut a_tp = protect_vec(&a);
                        let mut b_tp = protect_vec(&b);

                        if a.len() != b.len() {
                            return quickcheck::TestResult::must_fail(move || {
                                TpBool::protect(condition).cond_swap(&mut a_tp, &mut b_tp);
                            });
                        }

                        TpBool::protect(condition).cond_swap(&mut a_tp, &mut b_tp);

                        let a_after = expose_vec(&a_tp);
                        let b_after = expose_vec(&b_tp);

                        quickcheck::TestResult::from_bool(
                            if condition {
                                (a_after == b) && (b_after == a)
                            } else {
                                (a_after == a) && (b_after == b)
                            }
                        )
                    }

                    fn select(condition: bool, a: $type, b: $type) -> bool {
                        let a_tp = $tp_type::protect(a);
                        let b_tp = $tp_type::protect(b);

                        let selected = TpBool::protect(condition).select(a_tp, b_tp).expose();

                        if condition {
                            selected == a
                        } else {
                            selected == b
                        }
                    }

                    fn select_vec(condition: bool, a: Vec<$type>, b: Vec<$type>) -> quickcheck::TestResult {
                        let a_tp = protect_vec(&a);
                        let b_tp = protect_vec(&b);

                        if a.len() != b.len() {
                            return quickcheck::TestResult::must_fail(move || {
                                TpBool::protect(condition).select(a_tp, b_tp);
                            });
                        }

                        let selected_tp = TpBool::protect(condition).select(a_tp, b_tp);
                        let selected = expose_vec(&selected_tp);

                        quickcheck::TestResult::from_bool(
                            if condition {
                                selected == a
                            } else {
                                selected == b
                            }
                        )
                    }
                }
            }
        };
    }

    test_tp_cond_swap!(bool, TpBool, bool);
    test_tp_cond_swap!(u8, TpU8, u8);
    test_tp_cond_swap!(u16, TpU16, u16);
    test_tp_cond_swap!(u32, TpU32, u32);
    test_tp_cond_swap!(u64, TpU64, u64);
    test_tp_cond_swap!(i8, TpI8, i8);
    test_tp_cond_swap!(i16, TpI16, i16);
    test_tp_cond_swap!(i32, TpI32, i32);
    test_tp_cond_swap!(i64, TpI64, i64);
}
