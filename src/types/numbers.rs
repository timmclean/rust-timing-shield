use crate::util::impl_as;

macro_rules! define_number_type {
    (
        $tp_type:ident, $type:ident,
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
    }
}

define_number_type!(TpU8, u8, methods {
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpU16, u16, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpU32, u32, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpU64, u64, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpI8, i8, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpI16, i16, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI32, i32, as_i32);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpI32, i32, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI64, i64, as_i64);
});

define_number_type!(TpI64, i64, methods {
    impl_as!(TpU8,  u8,  as_u8);
    impl_as!(TpU16, u16, as_u16);
    impl_as!(TpU32, u32, as_u32);
    impl_as!(TpU64, u64, as_u64);
    impl_as!(TpI8,  i8,  as_i8);
    impl_as!(TpI16, i16, as_i16);
    impl_as!(TpI32, i32, as_i32);
});
