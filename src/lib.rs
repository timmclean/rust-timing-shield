// Copyright 2017-2022 Tim McLean

//! Comprehensive timing attack protection for Rust programs.
//!
//! Project home page: <https://www.chosenplaintext.ca/open-source/rust-timing-shield/>
//!
//! One of the fundamental challenges of writing software that operates on sensitive information
//! is preventing *timing leaks*. A timing leak is when there exists a relationship between the
//! values of secret variables in your program and the execution time of your code or other code
//! running on the same hardware. Attackers who are aware of this relationship can use a
//! high-resolution timer to learn secret information that they would not normally be able to
//! access (e.g. extract an SSL key from a web server).
//!
//! To prevent timing leaks in cryptography code, it is best practice to write code that is
//! *constant-time*. For a full background on writing constant-time code, see [A beginner's guide
//! to constant-time
//! cryptography](https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html).
//!
//! `rust-timing-shield` is a framework for writing code without timing leaks.
//! See the [Getting Started
//! page](https://www.chosenplaintext.ca/open-source/rust-timing-shield/getting-started) for more
//! information.

#[cfg(test)]
extern crate quickcheck;

pub mod barriers;
mod cond_swap;
mod eq;
mod ord;
mod types;
mod util;

use std::ops::Add;
use std::ops::AddAssign;
use std::ops::BitAnd;
use std::ops::BitAndAssign;
use std::ops::BitOr;
use std::ops::BitOrAssign;
use std::ops::BitXor;
use std::ops::BitXorAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Neg;
use std::ops::Not;
use std::ops::Shl;
use std::ops::ShlAssign;
use std::ops::Shr;
use std::ops::ShrAssign;
use std::ops::Sub;
use std::ops::SubAssign;

pub use crate::cond_swap::TpCondSwap;
pub use crate::eq::TpEq;
pub use crate::ord::TpOrd;
pub use crate::types::{bool::*, numbers::*};

macro_rules! impl_unary_op {
    (
        $trait_name:ident, $op_name:ident,
        $input_type:ident, $output_type:ident,
        ($input_var:ident) => $input_expr:expr,
        ($output_var:ident) => $output_expr:expr
    ) => {
        impl $trait_name for $input_type {
            type Output = $output_type;

            #[inline(always)]
            fn $op_name(self) -> $output_type {
                let $input_var = self;
                let $output_var = ($input_expr).$op_name();
                $output_expr
            }
        }
    };
}

macro_rules! impl_bin_op {
    (
        $trait_name:ident, $outer_op_name:ident, $inner_op_name:ident, $output_type:ident,
        ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
        ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr,
        ($output_var:ident) => $output_expr:expr
    ) => {
        impl $trait_name<$rhs_type> for $lhs_type {
            type Output = $output_type;

            #[inline(always)]
            fn $outer_op_name(self, other: $rhs_type) -> $output_type {
                let lhs = {
                    let $lhs_var = self;
                    $lhs_expr
                };
                let rhs = {
                    let $rhs_var = other;
                    $rhs_expr
                };
                let $output_var = lhs.$inner_op_name(rhs);
                $output_expr
            }
        }
    };
}

macro_rules! derive_assign_op {
    (
        $trait_name:ident, $assign_op_name:ident, $op_name:ident,
        $lhs_type:ty, $rhs_type:ty
    ) => {
        impl $trait_name<$rhs_type> for $lhs_type {
            #[inline(always)]
            fn $assign_op_name(&mut self, rhs: $rhs_type) {
                *self = self.$op_name(rhs);
            }
        }
    };
}

macro_rules! impl_unary_op_for_number {
    (
        $trait_name:ident, $op_name:ident,
        $input_type:ident, $output_type:ident
    ) => {
        impl_unary_op!(
            $trait_name, $op_name, $input_type, $output_type,
            (input) => input.expose(),
            (output) => $output_type::protect(output)
        );
    }
}

macro_rules! impl_all_bin_op_for_number {
    (
        $tp_type:ident, $type:ident,
        $trait_name:ident, $outer_op_name:ident, $inner_op_name:ident
    ) => {
        impl_bin_op!(
            $trait_name, $outer_op_name, $inner_op_name, $tp_type,
            (l: $tp_type) => l.expose(),
            (r: $tp_type) => r.expose(),
            (output) => $tp_type::protect(output)
        );
        impl_bin_op!(
            $trait_name, $outer_op_name, $inner_op_name, $tp_type,
            (l: $type) => l,
            (r: $tp_type) => r.expose(),
            (output) => $tp_type::protect(output)
        );
        impl_bin_op!(
            $trait_name, $outer_op_name, $inner_op_name, $tp_type,
            (l: $tp_type) => l.expose(),
            (r: $type) => r,
            (output) => $tp_type::protect(output)
        );
    }
}

macro_rules! impl_all_ops_for_number {
    ($tp_type:ident, $type:ident) => {
        impl_unary_op!(
            Not, not, $tp_type, $tp_type,
            (input) => input.expose(),
            (output) => $tp_type::protect(output)
        );

        impl_all_bin_op_for_number!($tp_type, $type, Add, add, wrapping_add);
        impl_all_bin_op_for_number!($tp_type, $type, Sub, sub, wrapping_sub);
        impl_all_bin_op_for_number!($tp_type, $type, Mul, mul, wrapping_mul);
        impl_all_bin_op_for_number!($tp_type, $type, BitAnd, bitand, bitand);
        impl_all_bin_op_for_number!($tp_type, $type, BitOr, bitor, bitor);
        impl_all_bin_op_for_number!($tp_type, $type, BitXor, bitxor, bitxor);

        impl_bin_op!(
            Shl, shl, wrapping_shl, $tp_type,
            (l: $tp_type) => l.expose(),
            (r: u32) => r,
            (output) => $tp_type::protect(output)
        );

        impl_bin_op!(
            Shr, shr, wrapping_shr, $tp_type,
            (l: $tp_type) => l.expose(),
            (r: u32) => r,
            (output) => $tp_type::protect(output)
        );

        derive_assign_op!(AddAssign, add_assign, add, $tp_type, $tp_type);
        derive_assign_op!(AddAssign, add_assign, add, $tp_type, $type);

        derive_assign_op!(SubAssign, sub_assign, sub, $tp_type, $tp_type);
        derive_assign_op!(SubAssign, sub_assign, sub, $tp_type, $type);

        derive_assign_op!(MulAssign, mul_assign, mul, $tp_type, $tp_type);
        derive_assign_op!(MulAssign, mul_assign, mul, $tp_type, $type);

        derive_assign_op!(BitAndAssign, bitand_assign, bitand, $tp_type, $tp_type);
        derive_assign_op!(BitAndAssign, bitand_assign, bitand, $tp_type, $type);

        derive_assign_op!(BitOrAssign, bitor_assign, bitor, $tp_type, $tp_type);
        derive_assign_op!(BitOrAssign, bitor_assign, bitor, $tp_type, $type);

        derive_assign_op!(BitXorAssign, bitxor_assign, bitxor, $tp_type, $tp_type);
        derive_assign_op!(BitXorAssign, bitxor_assign, bitxor, $tp_type, $type);

        derive_assign_op!(ShlAssign, shl_assign, shl, $tp_type, u32);
        derive_assign_op!(ShrAssign, shr_assign, shr, $tp_type, u32);
    }
}

impl_all_ops_for_number!(TpU8, u8);
impl_all_ops_for_number!(TpU16, u16);
impl_all_ops_for_number!(TpU32, u32);
impl_all_ops_for_number!(TpU64, u64);
impl_all_ops_for_number!(TpI8, i8);
impl_all_ops_for_number!(TpI16, i16);
impl_all_ops_for_number!(TpI32, i32);
impl_all_ops_for_number!(TpI64, i64);

impl_unary_op_for_number!(Neg, neg, TpI8, TpI8);
impl_unary_op_for_number!(Neg, neg, TpI16, TpI16);
impl_unary_op_for_number!(Neg, neg, TpI32, TpI32);
impl_unary_op_for_number!(Neg, neg, TpI64, TpI64);

macro_rules! impl_all_bin_op_for_bool {
    ($trait_name:ident, $op_name:ident) => {
        impl_all_bin_op_for_bool!($trait_name, $op_name, $op_name);
    };
    ($trait_name:ident, $outer_op_name:ident, $inner_op_name:ident) => {
        impl_bin_op!(
            $trait_name,
            $outer_op_name,
            $inner_op_name,
            TpBool,
            (l: TpBool) => l.expose_u8_unprotected(),
            (r: TpBool) => r.expose_u8_unprotected(),
            (b) => unsafe { TpBool::from_u8_unchecked(b) }
        );
        impl_bin_op!(
            $trait_name,
            $outer_op_name,
            $inner_op_name,
            TpBool,
            (l: bool) => l as u8,
            (r: TpBool) => r.expose_u8_unprotected(),
            (b) => unsafe { TpBool::from_u8_unchecked(b) }
        );
        impl_bin_op!(
            $trait_name,
            $outer_op_name,
            $inner_op_name,
            TpBool,
            (l: TpBool) => l.expose_u8_unprotected(),
            (r: bool) => r as u8,
            (b) => unsafe { TpBool::from_u8_unchecked(b) }
        );
    };
}

impl Not for TpBool {
    type Output = TpBool;

    #[inline(always)]
    fn not(self) -> TpBool {
        unsafe { TpBool::from_u8_unchecked(self.expose_u8_unprotected() ^ 0x01) }
    }
}

impl_all_bin_op_for_bool!(BitAnd, bitand);
impl_all_bin_op_for_bool!(BitOr, bitor);
impl_all_bin_op_for_bool!(BitXor, bitxor);

derive_assign_op!(BitAndAssign, bitand_assign, bitand, TpBool, TpBool);
derive_assign_op!(BitAndAssign, bitand_assign, bitand, TpBool, bool);

derive_assign_op!(BitOrAssign, bitor_assign, bitor, TpBool, TpBool);
derive_assign_op!(BitOrAssign, bitor_assign, bitor, TpBool, bool);

derive_assign_op!(BitXorAssign, bitxor_assign, bitxor, TpBool, TpBool);
derive_assign_op!(BitXorAssign, bitxor_assign, bitxor, TpBool, bool);

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    // The separate modules in the tests below are to work around limitations of Rust macros
    // (concat_idents does not work in function definitions)

    macro_rules! test_tp_eq {
        (
            $test_name:ident,
            ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
            ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr
        ) => {
            quickcheck! {
                fn $test_name(lhs: $lhs_type, rhs: $rhs_type) -> bool {
                    let lhs_tp = {
                        let $lhs_var = lhs.clone();
                        $lhs_expr
                    };
                    let rhs_tp = {
                        let $rhs_var = rhs.clone();
                        $rhs_expr
                    };
                    ((lhs == rhs) == (lhs_tp.tp_eq(&rhs_tp).expose()))
                        && ((lhs != rhs) == (lhs_tp.tp_not_eq(&rhs_tp).expose()))
                }
            }
        };
    }

    macro_rules! test_tp_ord {
        (
            $test_name:ident,
            ($lhs_var:ident : $lhs_type:ident) => $lhs_expr:expr,
            ($rhs_var:ident : $rhs_type:ident) => $rhs_expr:expr
        ) => {
            mod $test_name {
                use super::*;
                quickcheck! {
                    fn test_tp_lt(lhs: $lhs_type, rhs: $rhs_type) -> bool {
                        let lhs_tp = {
                            let $lhs_var = lhs;
                            $lhs_expr
                        };
                        let rhs_tp = {
                            let $rhs_var = rhs;
                            $rhs_expr
                        };
                        (lhs < rhs) == (lhs_tp.tp_lt(&rhs_tp).expose())
                    }

                    fn test_tp_gt(lhs: $lhs_type, rhs: $rhs_type) -> bool {
                        let lhs_tp = {
                            let $lhs_var = lhs;
                            $lhs_expr
                        };
                        let rhs_tp = {
                            let $rhs_var = rhs;
                            $rhs_expr
                        };
                        (lhs > rhs) == (lhs_tp.tp_gt(&rhs_tp).expose())
                    }

                    fn test_tp_lt_eq(lhs: $lhs_type, rhs: $rhs_type) -> bool {
                        let lhs_tp = {
                            let $lhs_var = lhs;
                            $lhs_expr
                        };
                        let rhs_tp = {
                            let $rhs_var = rhs;
                            $rhs_expr
                        };
                        (lhs <= rhs) == (lhs_tp.tp_lt_eq(&rhs_tp).expose())
                    }

                    fn test_tp_gt_eq(lhs: $lhs_type, rhs: $rhs_type) -> bool {
                        let lhs_tp = {
                            let $lhs_var = lhs;
                            $lhs_expr
                        };
                        let rhs_tp = {
                            let $rhs_var = rhs;
                            $rhs_expr
                        };
                        (lhs >= rhs) == (lhs_tp.tp_gt_eq(&rhs_tp).expose())
                    }
                }
            }
        };
    }
    macro_rules! test_number_type {
        ($tp_type:ident, $type:ident, $test_mod:ident) => {
            mod $test_mod {
                use super::*;

                mod ops {
                    use super::*;

                    fn protect(x: $type) -> $tp_type {
                        $tp_type::protect(x)
                    }

                    quickcheck! {
                        fn not(x: $type) -> bool {
                            (!x) == (!protect(x)).expose()
                        }

                        fn add_no_leak(l: $type, r: $type) -> bool {
                            (l.wrapping_add(r)) == (protect(l) + protect(r)).expose()
                        }
                        fn add_leak_lhs(l: $type, r: $type) -> bool {
                            (l.wrapping_add(r)) == (l + protect(r)).expose()
                        }
                        fn add_leak_rhs(l: $type, r: $type) -> bool {
                            (l.wrapping_add(r)) == (protect(l) + r).expose()
                        }

                        fn sub_no_leak(l: $type, r: $type) -> bool {
                            (l.wrapping_sub(r)) == (protect(l) - protect(r)).expose()
                        }
                        fn sub_leak_lhs(l: $type, r: $type) -> bool {
                            (l.wrapping_sub(r)) == (l - protect(r)).expose()
                        }
                        fn sub_leak_rhs(l: $type, r: $type) -> bool {
                            (l.wrapping_sub(r)) == (protect(l) - r).expose()
                        }

                        fn mul_no_leak(l: $type, r: $type) -> bool {
                            (l.wrapping_mul(r)) == (protect(l) * protect(r)).expose()
                        }
                        fn mul_leak_lhs(l: $type, r: $type) -> bool {
                            (l.wrapping_mul(r)) == (l * protect(r)).expose()
                        }
                        fn mul_leak_rhs(l: $type, r: $type) -> bool {
                            (l.wrapping_mul(r)) == (protect(l) * r).expose()
                        }

                        fn bitand_no_leak(l: $type, r: $type) -> bool {
                            (l & r) == (protect(l) & protect(r)).expose()
                        }
                        fn bitand_leak_lhs(l: $type, r: $type) -> bool {
                            (l & r) == (l & protect(r)).expose()
                        }
                        fn bitand_leak_rhs(l: $type, r: $type) -> bool {
                            (l & r) == (protect(l) & r).expose()
                        }

                        fn bitor_no_leak(l: $type, r: $type) -> bool {
                            (l | r) == (protect(l) | protect(r)).expose()
                        }
                        fn bitor_leak_lhs(l: $type, r: $type) -> bool {
                            (l | r) == (l | protect(r)).expose()
                        }
                        fn bitor_leak_rhs(l: $type, r: $type) -> bool {
                            (l | r) == (protect(l) | r).expose()
                        }

                        fn bitxor_no_leak(l: $type, r: $type) -> bool {
                            (l ^ r) == (protect(l) ^ protect(r)).expose()
                        }
                        fn bitxor_leak_lhs(l: $type, r: $type) -> bool {
                            (l ^ r) == (l ^ protect(r)).expose()
                        }
                        fn bitxor_leak_rhs(l: $type, r: $type) -> bool {
                            (l ^ r) == (protect(l) ^ r).expose()
                        }

                        fn shl_leak_rhs(l: $type, r: u32) -> bool {
                            let bits = $type::count_zeros(0);
                            (l << (r % bits)) == (protect(l) << r).expose()
                        }

                        fn shr_leak_rhs(l: $type, r: u32) -> bool {
                            let bits = $type::count_zeros(0);
                            (l >> (r % bits)) == (protect(l) >> r).expose()
                        }

                        fn rotate_left_leak_rhs(l: $type, r: u32) -> bool {
                            let bits = $type::count_zeros(0);
                            (l.rotate_left(r % bits)) == protect(l).rotate_left(r).expose()
                        }

                        fn rotate_right_leak_rhs(l: $type, r: u32) -> bool {
                            let bits = $type::count_zeros(0);
                            (l.rotate_right(r % bits)) == protect(l).rotate_right(r).expose()
                        }
                    }
                }

                mod tp_eq {
                    use super::*;

                    test_tp_eq!(
                        no_leak,
                        (l: $type) => $tp_type::protect(l),
                        (r: $type) => $tp_type::protect(r)
                    );
                    test_tp_eq!(
                        leak_lhs,
                        (l: $type) => l,
                        (r: $type) => $tp_type::protect(r)
                    );
                    test_tp_eq!(
                        leak_rhs,
                        (l: $type) => $tp_type::protect(l),
                        (r: $type) => r
                    );

                }

                // Numeric types have a specialized implementation of TpEq for slices, so we'll
                // test that separately.
                mod slice_tp_eq {
                    use super::*;

                    quickcheck! {
                        fn no_leak(l: Vec<$type>, r: Vec<$type>) -> bool {
                            let lhs = l.clone()
                                .into_iter()
                                .map(|n| $tp_type::protect(n))
                                .collect::<Vec<_>>();
                            let rhs = r.clone()
                                .into_iter()
                                .map(|n| $tp_type::protect(n))
                                .collect::<Vec<_>>();
                            let lhs_slice: &[_] = &lhs;
                            let rhs_slice: &[_] = &rhs;

                            ((l == r) == (lhs_slice.tp_eq(&rhs_slice).expose()))
                                && ((l != r) == (lhs_slice.tp_not_eq(&rhs_slice).expose()))
                        }

                        fn leak_lhs(l: Vec<$type>, r: Vec<$type>) -> bool {
                            let rhs = r.clone()
                                .into_iter()
                                .map(|n| $tp_type::protect(n))
                                .collect::<Vec<_>>();
                            let lhs_slice: &[_] = &l;
                            let rhs_slice: &[_] = &rhs;

                            ((l == r) == (lhs_slice.tp_eq(&rhs_slice).expose()))
                                && ((l != r) == (lhs_slice.tp_not_eq(&rhs_slice).expose()))
                        }

                        fn leak_rhs(l: Vec<$type>, r: Vec<$type>) -> bool {
                            let lhs = l.clone()
                                .into_iter()
                                .map(|n| $tp_type::protect(n))
                                .collect::<Vec<_>>();
                            let lhs_slice: &[_] = &lhs;
                            let rhs_slice: &[_] = &r;

                            ((l == r) == (lhs_slice.tp_eq(&rhs_slice).expose()))
                                && ((l != r) == (lhs_slice.tp_not_eq(&rhs_slice).expose()))
                        }
                    }
                }

                mod tp_ord {
                    use super::*;

                    test_tp_ord!(
                        no_leak,
                        (l: $type) => $tp_type::protect(l),
                        (r: $type) => $tp_type::protect(r)
                    );
                    test_tp_ord!(
                        leak_lhs,
                        (l: $type) => l,
                        (r: $type) => $tp_type::protect(r)
                    );
                    test_tp_ord!(
                        leak_rhs,
                        (l: $type) => $tp_type::protect(l),
                        (r: $type) => r
                    );
                }

                mod tp_cond_swap {
                    use super::*;

                    quickcheck! {
                        fn test(condition: bool, a: $type, b: $type) -> bool {
                            let mut swap1 = $tp_type::protect(a);
                            let mut swap2 = $tp_type::protect(b);
                            TpBool::protect(condition).cond_swap(&mut swap1, &mut swap2);
                            if condition {
                                (swap1.expose() == b) && (swap2.expose() == a)
                            } else {
                                (swap1.expose() == a) && (swap2.expose() == b)
                            }
                        }
                    }
                }
            }
        }
    }

    test_number_type!(TpU8, u8, u8_tests);
    test_number_type!(TpU16, u16, u16_tests);
    test_number_type!(TpU32, u32, u32_tests);
    test_number_type!(TpU64, u64, u64_tests);
    test_number_type!(TpI8, i8, i8_tests);
    test_number_type!(TpI16, i16, i16_tests);
    test_number_type!(TpI32, i32, i32_tests);
    test_number_type!(TpI64, i64, i64_tests);

    // negation tests are separate because unsigned types don't impl Neg
    quickcheck! {
        fn i8_neg(x: i8) -> bool {
            (-x) == (-TpI8::protect(x)).expose()
        }
        fn i16_neg(x: i16) -> bool {
            (-x) == (-TpI16::protect(x)).expose()
        }
        fn i32_neg(x: i32) -> bool {
            (-x) == (-TpI32::protect(x)).expose()
        }
        fn i64_neg(x: i64) -> bool {
            (-x) == (-TpI64::protect(x)).expose()
        }
    }

    mod tp_bool {
        use super::*;

        #[test]
        fn test_values() {
            assert_eq!(TP_FALSE.0, 0);
            assert_eq!(TP_TRUE.0, 1);
            assert_eq!(TpBool::protect(false).0, 0);
            assert_eq!(TpBool::protect(true).0, 1);
            assert_eq!(TP_FALSE.expose(), false);
            assert_eq!(TP_TRUE.expose(), true);
        }

        quickcheck! {
            fn tpbool_select(c: bool, a: u8, b: u8) -> bool {
                let tp_a = TpU8::protect(a);
                let tp_b = TpU8::protect(b);
                let result = TpBool::protect(c).select(tp_a, tp_b).expose();
                if c {
                    result == a
                } else {
                    result == b
                }
            }
        }

        #[test]
        fn test_not() {
            assert_eq!((!TP_FALSE).0, 1u8);
            assert_eq!((!TP_TRUE).0, 0u8);
        }

        fn protect(x: bool) -> TpBool {
            TpBool::protect(x)
        }

        quickcheck! {
            fn bitand_no_leak(l: bool, r: bool) -> bool {
                (l && r) == (protect(l) & protect(r)).expose()
            }
            fn bitand_leak_lhs(l: bool, r: bool) -> bool {
                (l && r) == (l & protect(r)).expose()
            }
            fn bitand_leak_rhs(l: bool, r: bool) -> bool {
                (l && r) == (protect(l) & r).expose()
            }

            fn bitor_no_leak(l: bool, r: bool) -> bool {
                (l || r) == (protect(l) | protect(r)).expose()
            }
            fn bitor_leak_lhs(l: bool, r: bool) -> bool {
                (l || r) == (l | protect(r)).expose()
            }
            fn bitor_leak_rhs(l: bool, r: bool) -> bool {
                (l || r) == (protect(l) | r).expose()
            }

            fn bitxor_no_leak(l: bool, r: bool) -> bool {
                (l ^ r) == (protect(l) ^ protect(r)).expose()
            }
            fn bitxor_leak_lhs(l: bool, r: bool) -> bool {
                (l ^ r) == (l ^ protect(r)).expose()
            }
            fn bitxor_leak_rhs(l: bool, r: bool) -> bool {
                (l ^ r) == (protect(l) ^ r).expose()
            }
        }

        quickcheck! {
            fn tp_eq_no_leak(a: bool, b: bool) -> bool {
                let tp_a = protect(a);
                let tp_b = protect(b);
                (a == b) == (tp_a.tp_eq(&tp_b).expose())
            }
            fn tp_eq_leak_lhs(a: bool, b: bool) -> bool {
                let tp_b = protect(b);
                (a == b) == (a.tp_eq(&tp_b).expose())
            }
            fn tp_eq_leak_rhs(a: bool, b: bool) -> bool {
                let tp_a = protect(a);
                (a == b) == (tp_a.tp_eq(&b).expose())
            }
        }

        quickcheck! {
            fn tp_cond_swap(swap: bool, a: bool, b: bool) -> bool {
                let mut swap1 = protect(a);
                let mut swap2 = protect(b);
                protect(swap).cond_swap(&mut swap1, &mut swap2);
                if swap {
                    (swap1.expose() == b) && (swap2.expose() == a)
                } else {
                    (swap1.expose() == a) && (swap2.expose() == b)
                }
            }
        }

        mod slice_tp_eq {
            use super::*;

            quickcheck! {
                fn no_leak(l: Vec<bool>, r: Vec<bool>) -> bool {
                    let lhs = l.clone()
                        .into_iter()
                        .map(|n| TpBool::protect(n))
                        .collect::<Vec<_>>();
                    let rhs = r.clone()
                        .into_iter()
                        .map(|n| TpBool::protect(n))
                        .collect::<Vec<_>>();
                    let lhs_slice: &[_] = &lhs;
                    let rhs_slice: &[_] = &rhs;

                    ((l == r) == (lhs_slice.tp_eq(&rhs_slice).expose()))
                        && ((l != r) == (lhs_slice.tp_not_eq(&rhs_slice).expose()))
                }

                fn leak_lhs(l: Vec<bool>, r: Vec<bool>) -> bool {
                    let rhs = r.clone()
                        .into_iter()
                        .map(|n| TpBool::protect(n))
                        .collect::<Vec<_>>();
                    let lhs_slice: &[_] = &l;
                    let rhs_slice: &[_] = &rhs;

                    ((l == r) == (lhs_slice.tp_eq(&rhs_slice).expose()))
                        && ((l != r) == (lhs_slice.tp_not_eq(&rhs_slice).expose()))
                }

                fn leak_rhs(l: Vec<bool>, r: Vec<bool>) -> bool {
                    let lhs = l.clone()
                        .into_iter()
                        .map(|n| TpBool::protect(n))
                        .collect::<Vec<_>>();
                    let lhs_slice: &[_] = &lhs;
                    let rhs_slice: &[_] = &r;

                    ((l == r) == (lhs_slice.tp_eq(&rhs_slice).expose()))
                        && ((l != r) == (lhs_slice.tp_not_eq(&rhs_slice).expose()))
                }
            }
        }
    }

    quickcheck! {
        fn tp_cond_swap_slices(swap: bool, a: Vec<u8>, b: Vec<u8>) -> quickcheck::TestResult {
            if a.len() != b.len() {
                return quickcheck::TestResult::discard();
            }

            let mut swap1 = a.iter().map(|&x| TpU8::protect(x)).collect::<Vec<_>>();
            let mut swap2 = b.iter().map(|&x| TpU8::protect(x)).collect::<Vec<_>>();
            {
                let slice_ref1: &mut [TpU8] = &mut *swap1;
                let slice_ref2: &mut [TpU8] = &mut *swap2;
                TpBool::protect(swap).cond_swap(slice_ref1, slice_ref2);
            }
            let res1: Vec<_> = swap1.iter().map(|x| x.expose()).collect();
            let res2: Vec<_> = swap2.iter().map(|x| x.expose()).collect();
            quickcheck::TestResult::from_bool(
                if swap {
                    (res1 == b) && (res2 == a)
                } else {
                    (res1 == a) && (res2 == b)
                }
            )
        }

        fn tp_cond_swap_vecs(swap: bool, a: Vec<u8>, b: Vec<u8>) -> quickcheck::TestResult {
            if a.len() != b.len() {
                return quickcheck::TestResult::discard();
            }

            let mut swap1 = a.iter().map(|&x| TpU8::protect(x)).collect::<Vec<_>>();
            let mut swap2 = b.iter().map(|&x| TpU8::protect(x)).collect::<Vec<_>>();
            {
                let vec_ref1: &mut Vec<TpU8> = &mut swap1;
                let vec_ref2: &mut Vec<TpU8> = &mut swap2;
                TpBool::protect(swap).cond_swap(vec_ref1, vec_ref2);
            }
            let res1: Vec<_> = swap1.iter().map(|x| x.expose()).collect();
            let res2: Vec<_> = swap2.iter().map(|x| x.expose()).collect();
            quickcheck::TestResult::from_bool(
                if swap {
                    (res1 == b) && (res2 == a)
                } else {
                    (res1 == a) && (res2 == b)
                }
            )
        }
    }
}

// TODO assume barrel shifter on x86?
// TODO impl TpCondSwap for tuples
// TODO explain downsides (e.g. secret constants will get leaked through constant
// folding/propagation)
