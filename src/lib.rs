// Copyright 2017-2021 Tim McLean

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

#![feature(asm, min_specialization)]

#[cfg(test)]
extern crate quickcheck;

pub mod barriers;

use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Sub;
use std::ops::SubAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::BitAnd;
use std::ops::BitAndAssign;
use std::ops::BitOr;
use std::ops::BitOrAssign;
use std::ops::BitXor;
use std::ops::BitXorAssign;
use std::ops::Shl;
use std::ops::ShlAssign;
use std::ops::Shr;
use std::ops::ShrAssign;
use std::ops::Neg;
use std::ops::Not;

use barriers::optimization_barrier_u8;

macro_rules! impl_unary_op {
    (
        $trait_name:ident, $op_name:ident,
        $input_type:ident, $output_type:ident
    ) => {
        impl $trait_name for $input_type {
            type Output = $output_type;

            #[inline(always)]
            fn $op_name(self) -> $output_type {
                $output_type((self.0).$op_name())
            }
        }
    }
}

macro_rules! impl_bin_op {
    (
        $trait_name:ident, $op_name:ident, $output_type:ident,
        ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
        ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr
    ) => {
        impl_bin_op!(
            $trait_name, $op_name, $op_name, $output_type,
            ($lhs_var: $lhs_type) => $lhs_expr,
            ($rhs_var: $rhs_type) => $rhs_expr,
            (output) => output
        );
    };
    (
        $trait_name:ident, $op_name:ident, $output_type:ident,
        ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
        ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr,
        ($output_var:ident) => $output_expr:expr
    ) => {
        impl_bin_op!(
            $trait_name, $op_name, $op_name, $output_type,
            ($lhs_var: $lhs_type) => $lhs_expr,
            ($rhs_var: $rhs_type) => $rhs_expr,
            ($output_var) => $output_expr
        );
    };
    (
        $trait_name:ident, $outer_op_name:ident, $inner_op_name:ident, $output_type:ident,
        ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
        ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr
    ) => {
        impl_bin_op!(
            $trait_name, $outer_op_name, $inner_op_name, $output_type,
            ($lhs_var: $lhs_type) => $lhs_expr,
            ($rhs_var: $rhs_type) => $rhs_expr,
            (output) => output
        );
    };
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
                $output_type($output_expr)
            }
        }
    }
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
    }
}

macro_rules! impl_as {
    ($tp_type:ident, $type:ident, $fn_name:ident) => {
        /// Casts from one number type to another, following the same conventions as Rust's `as`
        /// keyword.
        #[inline(always)]
        pub fn $fn_name(self) -> $tp_type {
            $tp_type(self.0 as $type)
        }
    }
}

macro_rules! as_unsigned_type {
    (u8 ) => {u8 };
    (u16) => {u16};
    (u32) => {u32};
    (u64) => {u64};
    (i8 ) => {u8 };
    (i16) => {u16};
    (i32) => {u32};
    (i64) => {u64};
}

macro_rules! impl_tp_eq {
    (
        $lhs_type:ty, $rhs_type:ty,
        ($lhs_var:ident, $rhs_var:ident) => $eq_expr:expr
    ) => {
        impl TpEq<$rhs_type> for $lhs_type {
            #[inline(always)]
            fn tp_eq(&self, other: &$rhs_type) -> TpBool {
                let $lhs_var = self;
                let $rhs_var = other;
                $eq_expr
            }

            #[inline(always)]
            fn tp_not_eq(&self, other: &$rhs_type) -> TpBool {
                // TODO might not be optimal
                !self.tp_eq(other)
            }
        }
    }
}

macro_rules! impl_tp_eq_for_number {
    (
        $inner_type:ident,
        ($lhs_var:ident : $lhs_type:ty) => $lhs_expr:expr,
        ($rhs_var:ident : $rhs_type:ty) => $rhs_expr:expr
    ) => {
        impl_tp_eq!($lhs_type, $rhs_type, (lhs, rhs) => {
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
            TpBool((unsigned_msb_iff_zero_diff >> (type_bitwidth - 1)) as u8)
        });
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

            #[inline(always)]
            fn tp_lt_eq(&self, other: &$rhs_type) -> TpBool {
                // TODO might not be optimal
                !self.tp_gt(other)
            }

            #[inline(always)]
            fn tp_gt_eq(&self, other: &$rhs_type) -> TpBool {
                // TODO might not be optimal
                !self.tp_lt(other)
            }
        }
    }
}

macro_rules! impl_tp_cond_swap_with_xor {
    ($tp_type:ident, $type:ident) => {
        impl TpCondSwap for $tp_type {
            #[inline(always)]
            fn tp_cond_swap(condition: TpBool, a: &mut $tp_type, b: &mut $tp_type) {
                // Zero-extend condition to this type's width
                let cond_zx = $tp_type(condition.0 as $type);

                // Create mask of 11...11 for true or 00...00 for false
                let mask = !(cond_zx - 1);

                // swapper will be a XOR b for true or 00...00 for false
                let swapper = (*a ^ *b) & mask;

                *a ^= swapper;
                *b ^= swapper;
            }
        }
    }
}

macro_rules! define_number_type {
    (
        $tp_type:ident, $type:ident,
        tp_lt($tp_lt_lhs_var:ident, $tp_lt_rhs_var:ident) => $tp_lt_expr:expr,
        methods {
            $($methods:tt)*
        }
    ) => {
        /// A number type that prevents its value from being leaked to attackers through timing
        /// information.
        ///
        /// Use this type's `protect` method as early as possible to prevent the value from being
        /// used in variable-time computations.
        ///
        /// Unlike Rust's built-in number types, `rust-timing-shield` number types have no overflow
        /// checking, even in debug mode. In other words, they behave like Rust's
        /// [Wrapping](https://doc.rust-lang.org/std/num/struct.Wrapping.html) types.
        ///
        /// Additionally, all shift distances are reduced mod the bit width of the type
        /// (e.g. `some_i64 << 104` is equivalent to `some_i64 << 40`).
        ///
        /// ```
        /// # use timing_shield::*;
        /// # let some_u8 = 5u8;
        /// # let some_other_u8 = 20u8;
        /// // Protect the value as early as possible to limit the risk
        /// let protected_value = TpU8::protect(some_u8);
        /// let other_protected_value = TpU8::protect(some_other_u8);
        ///
        /// // Do some computation with the protected values
        /// let x = (other_protected_value + protected_value) & 0x40;
        ///
        /// // If needed, remove protection using `expose`
        /// println!("{}", x.expose());
        /// ```
        #[cfg(target_arch = "x86_64")]
        #[derive(Clone, Copy)]
        pub struct $tp_type($type);

        impl $tp_type {
            /// Hide `input` behind a protective abstraction to prevent the value from being used
            /// in such a way that the value could leak out via a timing side channel.
            ///
            /// ```
            /// # use timing_shield::*;
            /// # let secret_u32 = 5u32;
            /// let protected = TpU32::protect(secret_u32);
            ///
            /// // Use `protected` instead of `secret_u32` to avoid timing leaks
            /// ```
            #[inline(always)]
            pub fn protect(input: $type) -> Self {
                $tp_type(input)
            }

            $($methods)*

            /// Shifts left by `n` bits, wrapping truncated bits around to the right side of the
            /// resulting value.
            ///
            /// If `n` is larger than the bitwidth of this number type,
            /// `n` is reduced mod that bitwidth.
            /// For example, rotating an `i16` with `n = 35` is equivalent to rotating with `n =
            /// 3`, since `35 = 3  mod 16`.
            #[inline(always)]
            pub fn rotate_left(self, n: u32) -> Self {
                $tp_type(self.0.rotate_left(n))
            }

            /// Shifts right by `n` bits, wrapping truncated bits around to the left side of the
            /// resulting value.
            ///
            /// If `n` is larger than the bitwidth of this number type,
            /// `n` is reduced mod that bitwidth.
            /// For example, rotating an `i16` with `n = 35` is equivalent to rotating with `n =
            /// 3`, since `35 = 3  mod 16`.
            #[inline(always)]
            pub fn rotate_right(self, n: u32) -> Self {
                $tp_type(self.0.rotate_right(n))
            }

            /// Remove the timing protection and expose the raw number value.
            /// Once a value is exposed, it is the library user's responsibility to prevent timing
            /// leaks (if necessary).
            ///
            /// Commonly, this method is used when a value is safe to make public (e.g. when an
            /// encryption algorithm outputs a ciphertext). Alternatively, this method may need to
            /// be used when providing a secret value to an interface that does not use
            /// `timing-shield`'s types (e.g. writing a secret key to a file using a file system
            /// API).
            #[inline(always)]
            pub fn expose(self) -> $type {
                self.0
            }
        }

        impl_unary_op!(Not, not, $tp_type, $tp_type);

        impl_bin_op!(Add, add, wrapping_add, $tp_type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_bin_op!(Add, add, wrapping_add, $tp_type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_bin_op!(Add, add, wrapping_add, $tp_type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_bin_op!(Sub, sub, wrapping_sub, $tp_type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_bin_op!(Sub, sub, wrapping_sub, $tp_type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_bin_op!(Sub, sub, wrapping_sub, $tp_type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_bin_op!(Mul, mul, wrapping_mul, $tp_type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_bin_op!(Mul, mul, wrapping_mul, $tp_type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_bin_op!(Mul, mul, wrapping_mul, $tp_type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_bin_op!(BitAnd, bitand, $tp_type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_bin_op!(BitAnd, bitand, $tp_type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_bin_op!(BitAnd, bitand, $tp_type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_bin_op!(BitOr, bitor, $tp_type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_bin_op!(BitOr, bitor, $tp_type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_bin_op!(BitOr, bitor, $tp_type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_bin_op!(BitXor, bitxor, $tp_type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_bin_op!(BitXor, bitxor, $tp_type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_bin_op!(BitXor, bitxor, $tp_type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_bin_op!(Shl, shl, wrapping_shl, $tp_type, (l: $tp_type) => l.0, (r: u32) => r);
        impl_bin_op!(Shr, shr, wrapping_shr, $tp_type, (l: $tp_type) => l.0, (r: u32) => r);

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

        impl_tp_eq_for_number!($type, (l: $tp_type) => l.0, (r: $tp_type) => r.0);
        impl_tp_eq_for_number!($type, (l: $type   ) => l  , (r: $tp_type) => r.0);
        impl_tp_eq_for_number!($type, (l: $tp_type) => l.0, (r: $type   ) => r  );

        impl_tp_ord!($tp_type, $tp_type, tp_lt(l, r) => {
            let $tp_lt_lhs_var = l.0;
            let $tp_lt_rhs_var = r.0;
            $tp_lt_expr
        });
        impl_tp_ord!($type, $tp_type, tp_lt(l, r) => {
            let $tp_lt_lhs_var = *l;
            let $tp_lt_rhs_var = r.0;
            $tp_lt_expr
        });
        impl_tp_ord!($tp_type, $type, tp_lt(l, r) => {
            let $tp_lt_lhs_var = l.0;
            let $tp_lt_rhs_var = *r;
            $tp_lt_expr
        });

        impl_tp_cond_swap_with_xor!($tp_type, $type);

        impl TpEq for [$tp_type] {
            #[inline(always)]
            fn tp_eq(&self, other: &[$tp_type]) -> TpBool {
                if self.len() != other.len() {
                    return TP_FALSE;
                }

                let acc = self.iter().zip(other.iter())
                    .fold($tp_type(0), |prev, (&a, &b)| prev | a ^ b);
                acc.tp_eq(&0)
            }

            #[inline(always)]
            fn tp_not_eq(&self, other: &[$tp_type]) -> TpBool {
                if self.len() != other.len() {
                    return TP_TRUE;
                }

                let acc = self.iter().zip(other.iter())
                    .fold($tp_type(0), |prev, (&a, &b)| prev | a ^ b);
                acc.tp_not_eq(&0)
            }
        }
    }
}

/// A trait for performing equality tests on types with timing leak protection.
///
/// **Important**: implementations of this trait are only required to protect inputs that are already a
/// timing-protected type. For example, `a.tp_eq(&b)` is allowed to leak `a` if `a` is a `u32`,
/// instead of a timing-protected type like `TpU32`.
///
/// Ideally, this trait will be removed in the future if/when Rust allows overloading of the `==`
/// and `!=` operators.
pub trait TpEq<Rhs=Self> where Rhs: ?Sized {
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
    fn tp_not_eq(&self, other: &Rhs) -> TpBool;
}

/// A trait for performing comparisons on types with timing leak protection.
///
/// **Important**: implementations of this trait are only required to protect inputs that are already a
/// timing-protected type. For example, `a.tp_lt(&b)` is allowed to leak `a` if `a` is a `u32`,
/// instead of a timing-protected type like `TpU32`.
///
/// Ideally, this trait will be removed in the future if/when Rust allows overloading of the `<`,
/// `>`, `<=`, and `>=` operators.
pub trait TpOrd<Rhs=Self> where Rhs: ?Sized {
    /// Compute `self < other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_lt(&self, other: &Rhs) -> TpBool;

    /// Compute `self <= other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_lt_eq(&self, other: &Rhs) -> TpBool;

    /// Compute `self > other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_gt(&self, other: &Rhs) -> TpBool;

    /// Compute `self >= other` without leaking the result.
    /// **Important**: if either input is not a timing-protected type, this operation might leak the
    /// value of that type. To prevent timing leaks, protect values before performing any operations
    /// on them.
    fn tp_gt_eq(&self, other: &Rhs) -> TpBool;
}

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
}

impl<T> TpEq for [T] where T: TpEq {
    #[inline(always)]
    default fn tp_eq(&self, other: &[T]) -> TpBool {
        if self.len() != other.len() {
            return TP_FALSE;
        }

        self.iter().zip(other.iter())
            .fold(TP_TRUE, |prev, (a, b)| prev & a.tp_eq(b))
    }

    #[inline(always)]
    default fn tp_not_eq(&self, other: &[T]) -> TpBool {
        if self.len() != other.len() {
            return TP_FALSE;
        }

        self.iter().zip(other.iter())
            .fold(TP_FALSE, |prev, (a, b)| prev | a.tp_not_eq(b))
    }
}

impl<T> TpEq for Vec<T> where T: TpEq {
    #[inline(always)]
    fn tp_eq(&self, other: &Vec<T>) -> TpBool {
        self[..].tp_eq(&other[..])
    }

    #[inline(always)]
    fn tp_not_eq(&self, other: &Vec<T>) -> TpBool {
        self[..].tp_not_eq(&other[..])
    }
}

impl<T> TpCondSwap for [T] where T: TpCondSwap {
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

impl<T> TpCondSwap for Vec<T> where T: TpCondSwap {
    #[inline(always)]
    fn tp_cond_swap(condition: TpBool, a: &mut Self, b: &mut Self) {
        condition.cond_swap(a.as_mut_slice(), b.as_mut_slice());
    }
}

define_number_type!(TpU8, u8, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u32).wrapping_sub(rhs as u32);
    TpBool((overflowing_iff_lt >> 31) as u8)
}, methods {
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpU16, u16, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u32).wrapping_sub(rhs as u32);
    TpBool((overflowing_iff_lt >> 31) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpU32, u32, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u64).wrapping_sub(rhs as u64);
    TpBool((overflowing_iff_lt >> 63) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpU64, u64, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = (lhs as u128).wrapping_sub(rhs as u128);
    TpBool((overflowing_iff_lt >> 127) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpI8, i8, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i32).wrapping_sub(rhs as i32)) as u32;
    TpBool((overflowing_iff_lt >> 31) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});
impl_unary_op!(Neg, neg, TpI8, TpI8);

define_number_type!(TpI16, i16, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i32).wrapping_sub(rhs as i32)) as u32;
    TpBool((overflowing_iff_lt >> 31) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});
impl_unary_op!(Neg, neg, TpI16, TpI16);

define_number_type!(TpI32, i32, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i64).wrapping_sub(rhs as i64)) as u64;
    TpBool((overflowing_iff_lt >> 63) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI64, i64, as_i64);
});
impl_unary_op!(Neg, neg, TpI32, TpI32);

define_number_type!(TpI64, i64, tp_lt(lhs, rhs) => {
    let overflowing_iff_lt = ((lhs as i128).wrapping_sub(rhs as i128)) as u128;
    TpBool((overflowing_iff_lt >> 127) as u8)
}, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
});
impl_unary_op!(Neg, neg, TpI64, TpI64);


/// A boolean type that prevents its value from being leaked to attackers through timing
/// information.
///
/// ```
/// # use timing_shield::*;
/// # let some_boolean = true;
/// let protected = TpBool::protect(some_boolean);
///
/// // Use `protected` from now on instead of `some_boolean`
/// ```
///
/// Use the `protect` method as early as possible in the computation for maximum protection:
///
/// ```
/// # use timing_shield::*;
/// # let some_boolean = true;
/// // DANGEROUS:
/// let badly_protected_boolean = TpU8::protect(some_boolean as u8);
///
/// // Safe:
/// let protected = TpBool::protect(some_boolean).as_u8();
/// # assert_eq!(protected.expose(), 1u8);
///
/// // DANGEROUS:
/// # let byte1 = 1u8;
/// # let byte2 = 2u8;
/// let badly_protected_value = TpBool::protect(byte1 == byte2);
/// # assert_eq!(badly_protected_value.expose(), false);
///
/// // Safe:
/// let protected_bool = TpU8::protect(byte1).tp_eq(&TpU8::protect(byte2));
/// # assert_eq!(protected_bool.expose(), false);
/// ```
///
/// Note that `&` and `|` are provided instead of `&&` and `||` because the usual boolean
/// short-circuiting behaviour leaks information about the values of the booleans.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub struct TpBool(u8);

static TP_FALSE: TpBool = TpBool(0);
static TP_TRUE: TpBool = TpBool(1);

impl TpBool {
    /// Hide `input` behind a protective abstraction to prevent the value from being used
    /// in such a way that the value could leak out via a timing side channel.
    ///
    /// ```
    /// # use timing_shield::*;
    /// # let some_secret_bool = true;
    /// let protected_bool = TpBool::protect(some_secret_bool);
    ///
    /// // Use `protected_bool` instead of `some_secret_bool` to avoid timing leaks
    /// ```
    #[inline(always)]
    pub fn protect(input: bool) -> Self {
        // `as u8` ensures value is 0 or 1
        // LLVM IR: input_u8 = zext i1 input to i8
        let input_u8 = input as u8;

        // Place an optimization barrier to hide that the u8 was originally a bool
        let input_u8 = optimization_barrier_u8(input_u8);

        TpBool(input_u8)
    }

    impl_as!(TpU8 , u8 , as_u8 );
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8 , i8 , as_i8 );
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);

    /// Remove the timing protection and expose the raw boolean value.
    /// Once the boolean is exposed, it is the library user's responsibility to prevent timing
    /// leaks (if necessary). Note: this can be very difficult to do correctly with boolean values.
    ///
    /// Commonly, this method is used when a value is safe to make public (e.g. the result of a
    /// signature verification).
    #[inline(always)]
    pub fn expose(self) -> bool {
        let bool_as_u8: u8 = optimization_barrier_u8(self.0);

        unsafe {
            // Safe as long as TpBool correctly maintains the invariant that self.0 is 0 or 1
            std::mem::transmute::<u8, bool>(bool_as_u8)
        }
    }

    /// Constant-time conditional swap. Swaps `a` and `b` if this boolean is true, otherwise has no
    /// effect. This operation is implemented without branching on the boolean value, and it will
    /// not leak information about whether the values were swapped.
    #[inline(always)]
    pub fn cond_swap<T>(self, a: &mut T, b: &mut T) where T: TpCondSwap + ?Sized {
        T::tp_cond_swap(self, a, b);
    }

    /// Returns one of the arguments, depending on the value of this boolean.
    /// The return value is selected without branching on the boolean value, and no information
    /// about which value was selected will be leaked.
    #[inline(always)]
    pub fn select<T>(self, when_true: T, when_false: T) -> T where T: TpCondSwap {
        // TODO is this optimal?
        // seems to compile to use NEG instead of DEC
        // NEG clobbers the carry flag, so arguably DEC could be better

        let mut result = when_false;
        let mut replace_with = when_true;
        self.cond_swap(&mut result, &mut replace_with);
        result
    }
}

impl Not for TpBool {
    type Output = TpBool;

    #[inline(always)]
    fn not(self) -> TpBool {
        TpBool(self.0 ^ 0x01)
    }
}

impl_bin_op!(BitAnd, bitand, TpBool, (l: TpBool) => l.0    , (r: TpBool) => r.0    );
impl_bin_op!(BitAnd, bitand, TpBool, (l:   bool) => l as u8, (r: TpBool) => r.0    );
impl_bin_op!(BitAnd, bitand, TpBool, (l: TpBool) => l.0    , (r:   bool) => r as u8);

impl_bin_op!(BitOr, bitor, TpBool, (l: TpBool) => l.0    , (r: TpBool) => r.0    );
impl_bin_op!(BitOr, bitor, TpBool, (l:   bool) => l as u8, (r: TpBool) => r.0    );
impl_bin_op!(BitOr, bitor, TpBool, (l: TpBool) => l.0    , (r:   bool) => r as u8);

impl_bin_op!(BitXor, bitxor, TpBool, (l: TpBool) => l.0    , (r: TpBool) => r.0    );
impl_bin_op!(BitXor, bitxor, TpBool, (l:   bool) => l as u8, (r: TpBool) => r.0    );
impl_bin_op!(BitXor, bitxor, TpBool, (l: TpBool) => l.0    , (r:   bool) => r as u8);

derive_assign_op!(BitAndAssign, bitand_assign, bitand, TpBool, TpBool);
derive_assign_op!(BitAndAssign, bitand_assign, bitand, TpBool, bool);

derive_assign_op!(BitOrAssign, bitor_assign, bitor, TpBool, TpBool);
derive_assign_op!(BitOrAssign, bitor_assign, bitor, TpBool, bool);

derive_assign_op!(BitXorAssign, bitxor_assign, bitxor, TpBool, TpBool);
derive_assign_op!(BitXorAssign, bitxor_assign, bitxor, TpBool, bool);

impl_tp_eq!(TpBool, TpBool, (l, r) => {
    l.bitxor(*r).not()
});
impl_tp_eq!(bool, TpBool, (l, r) => {
    TpBool((*l as u8) ^ r.0).not()
});
impl_tp_eq!(TpBool, bool, (l, r) => {
    TpBool(l.0 ^ (*r as u8)).not()
});

impl TpCondSwap for TpBool {
    #[inline(always)]
    fn tp_cond_swap(condition: TpBool, a: &mut TpBool, b: &mut TpBool) {
        let swapper = (*a ^ *b) & condition;
        *a ^= swapper;
        *b ^= swapper;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    // The separate modules in the tests below are to work around limitations of Rust macros
    // (concat_idents does not work in function definitions)

    macro_rules! test_tp_eq {
        (
            $test_name:ident,
            ($lhs_var:ident : $lhs_type:ident) => $lhs_expr:expr,
            ($rhs_var:ident : $rhs_type:ident) => $rhs_expr:expr
        ) => {
            quickcheck! {
                fn $test_name(lhs: $lhs_type, rhs: $rhs_type) -> bool {
                    let lhs_tp = {
                        let $lhs_var = lhs;
                        $lhs_expr
                    };
                    let rhs_tp = {
                        let $rhs_var = rhs;
                        $rhs_expr
                    };
                    (lhs == rhs) == (lhs_tp.tp_eq(&rhs_tp).expose())
                }
            }
        }
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
        }
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

    test_number_type!(TpU8 , u8 , u8_tests );
    test_number_type!(TpU16, u16, u16_tests);
    test_number_type!(TpU32, u32, u32_tests);
    test_number_type!(TpU64, u64, u64_tests);
    test_number_type!(TpI8 , i8 , i8_tests );
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
