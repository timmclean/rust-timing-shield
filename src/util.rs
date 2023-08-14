macro_rules! as_unsigned_type {
    (u8) => {
        u8
    };
    (u16) => {
        u16
    };
    (u32) => {
        u32
    };
    (u64) => {
        u64
    };
    (i8) => {
        u8
    };
    (i16) => {
        u16
    };
    (i32) => {
        u32
    };
    (i64) => {
        u64
    };
}
pub(crate) use as_unsigned_type;

macro_rules! impl_as {
    ($tp_type:ident, $type:ident, $fn_name:ident) => {
        /// Casts from one number type to another, following the same conventions as Rust's `as`
        /// keyword.
        #[inline(always)]
        pub fn $fn_name(self) -> $tp_type {
            $tp_type(self.0 as $type)
        }
    };
}
pub(crate) use impl_as;
