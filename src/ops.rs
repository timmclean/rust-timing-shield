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

use crate::TpBool;
use crate::TpI16;
use crate::TpI32;
use crate::TpI64;
use crate::TpI8;
use crate::TpU16;
use crate::TpU32;
use crate::TpU64;
use crate::TpU8;

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
    use crate::{TP_FALSE, TP_TRUE};
    use quickcheck::quickcheck;

    macro_rules! test_number_ops {
        ($tp_type:ident, $type:ident, $test_mod:ident) => {
            mod $test_mod {
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
        };
    }

    test_number_ops!(TpU8, u8, u8);
    test_number_ops!(TpU16, u16, u16);
    test_number_ops!(TpU32, u32, u32);
    test_number_ops!(TpU64, u64, u64);
    test_number_ops!(TpI8, i8, i8);
    test_number_ops!(TpI16, i16, i16);
    test_number_ops!(TpI32, i32, i32);
    test_number_ops!(TpI64, i64, i64);

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

    mod bool {
        use super::*;

        #[test]
        fn not() {
            assert_eq!((!TP_FALSE).as_u8().expose(), 1u8);
            assert_eq!((!TP_TRUE).as_u8().expose(), 0u8);
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
    }
}
