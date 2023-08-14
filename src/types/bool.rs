use crate::TpI16;
use crate::TpI32;
use crate::TpI64;
use crate::TpI8;
use crate::TpU16;
use crate::TpU32;
use crate::TpU64;
use crate::TpU8;
use crate::{barriers::optimization_barrier_u8, util::impl_as, TpCondSwap};

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
#[derive(Clone, Copy)]
pub struct TpBool(u8);

pub const TP_FALSE: TpBool = TpBool::FALSE;
pub const TP_TRUE: TpBool = TpBool::TRUE;

impl TpBool {
    pub const FALSE: Self = Self(0);
    pub const TRUE: Self = Self(1);

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

    #[inline(always)]
    pub(crate) unsafe fn from_u8_unchecked(input: u8) -> Self {
        Self(input)
    }

    impl_as!(TpU8, u8, as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8, i8, as_i8);
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

    #[inline(always)]
    pub(crate) fn expose_u8_unprotected(&self) -> u8 {
        self.0
    }

    /// Constant-time conditional swap. Swaps `a` and `b` if this boolean is true, otherwise has no
    /// effect. This operation is implemented without branching on the boolean value, and it will
    /// not leak information about whether the values were swapped.
    #[inline(always)]
    pub fn cond_swap<T>(self, a: &mut T, b: &mut T)
    where
        T: TpCondSwap + ?Sized,
    {
        TpCondSwap::tp_cond_swap(self, a, b);
    }

    /// Returns one of the arguments, depending on the value of this boolean.
    /// The return value is selected without branching on the boolean value, and no information
    /// about which value was selected will be leaked.
    #[inline(always)]
    pub fn select<T>(self, when_true: T, when_false: T) -> T
    where
        T: TpCondSwap,
    {
        TpCondSwap::select(self, when_true, when_false)
    }
}

#[cfg(test)]
mod tests {
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
}
