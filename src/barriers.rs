/// Identity function accepting a `u8` as input and outputting that same `u8` as
/// output, while blocking the compiler from applying optimizations across this node in the data
/// dependence graph.
///
/// This is an **internal utility** of rust-timing-shield that users of the framework will not
/// normally need to use.
///
/// # Background
///
/// rust-timing-shield has essentially two goals: (1) prevent the programmer from writing code that
/// they shouldn't, and (2) prevent the compiler from transforming a programmer's secure code
/// into vulnerable code. This function is a small primitive that assists in accomplishing the 2nd
/// goal.
///
/// An important rule of protecting code from timing attacks is to ensure that a program never
/// branches on a secret value. In rust-timing-shield terminology, we should never emit a
/// branch conditional on a `TpBool`. The Rust compiler uses many LLVM optimization passes that may
/// produce a conditional branch where none was written by the programmer, so we must remove the
/// compiler's ability to identify situations where a conditional branch could reasonably be
/// introduced. The most problematic optimizations identified so far output [an LLVM IR `select`
/// instruction](https://llvm.org/docs/LangRef.html#select-instruction).
///
/// Of course, it is legal for the compiler to emit `select` instructions in any situation as long
/// as the output and side effects of the code remain the same. For example, it could expand this
/// code:
///
/// ```
/// fn add(a: u8, b: u8) -> u8 {
///     a + b
/// }
/// ```
///
/// to:
///
/// ```
/// fn add(a: u8, b: u8) -> u8 {
///     if a == 5 && b == 5 {
///         return 10;
///     }
///     if a == 7 && b == 5 {
///         return 12;
///     }
///     a + b
/// }
/// ```
///
/// The current implementation of rust-timing-shield assumes that this is ridiculous and wouldn't
/// happen. In particular, an assumption is made that the compiler will only insert a `select` for
/// "values of boolean origin".  For example, this branchless code:
///
/// ```
/// fn add_bool(number: u8, b: bool) -> u8 {
///     number + (b as u8)
/// }
/// ```
///
/// could reasonably, under this assumption, be rewritten with a branch:
///
/// ```
/// fn add_bool(number: u8, b: bool) -> u8 {
///     if b {
///         return number + 1;
///     }
///
///     number
/// }
/// ```
///
/// since `b as u8` is a "value of boolean origin".  Based on the empirical tests of the Rust
/// compiler and a review of how LLVM optimization passes are implemented, this assumption appears
/// to be reasonable.
///
/// Now, with this assumption in place, rust-timing-shield only needs to ensure that all
/// timing-protected values either are not of boolean origin or hide their origin from the
/// compiler.  This is accomplished in two steps:
///
/// 1. All timing-protected boolean values (`TpBool`) are stored as `u8` values and never as
///    `bool`, even in intermediate computations.
/// 2. `TpBool::protect(bool)` converts the `bool` to a `u8` and uses an optimization barrier (this
///    function) to hide the origin of the `u8`.
///
/// # Usage
///
/// `optimization_barrier_u8` is a low-cost (but not zero-cost) way to hide a value's origin from the compiler. If a
/// value passes through an optimization barrier, the compiler will be able to perform
/// optimizations on computations prior to the barrier and optimizations on computations after the
/// barrier, but will be unable to perform optimizations *across* the barrier.
///
/// It is important that the barrier interrupt the flow of a value from one part of the program to
/// the next. As an example of incorrect usage:
///
/// ```
/// # use timing_shield::barriers::optimization_barrier_u8;
/// #
/// fn add_bool(number: u8, secret_condition: bool) -> u8 {
///     let secret_condition_u8 = secret_condition as u8;
///
///     // WRONG: barrier does not interrupt data flow
///     optimization_barrier_u8(secret_condition_u8);
///
///     number + secret_condition_u8
/// }
/// ```
///
/// Here, the return value from `optimization_barrier_u8` is unused, so the optimization barrier
/// has no effect. An optimization barrier must be the single connection between two parts of the
/// program's data dependence graph:
///
/// ```
/// # use timing_shield::barriers::optimization_barrier_u8;
/// #
/// fn add_bool(number: u8, secret_condition: bool) -> u8 {
///     let secret_condition_u8 = secret_condition as u8;
///
///     // Override the previous definition to avoid accidentally using the pre-barrier value
///     let secret_condition_u8 = optimization_barrier_u8(secret_condition_u8);
///
///     number + secret_condition_u8
/// }
/// ```
///
/// In rust-timing-shield, optimization barriers are used to hide when a `u8` is of boolean origin.
/// The use of a barrier prevents the compiler from identifying that the `u8` value after the
/// barrier is the same value that was cast from a `bool` before the barrier. This suppresses the
/// many optimizations that would transform the timing-leak-proof branchless computations with `u8`
/// values that rust-timing-shield produces into branching computations that leak boolean values.
///
/// # Performance considerations
///
/// `optimization_barrier_u8` is currently implemented as an empty inline assembly block. The `u8`
/// input value is provided as an input/output register to the assembly block and then immediately
/// returned as is. Although the assembly block is a no-op, LLVM is forced to assume that the value
/// may have changed and can make no assumptions about what the output may be. The Rust Unstable
/// reference [describes the assembly block as a black
/// box](https://doc.rust-lang.org/unstable-book/library-features/asm.html):
///
/// > &ldquo;The compiler cannot assume that the instructions in the asm are the ones that will
/// actually end up executed.  This effectively means that the compiler must treat the `asm!` as a
/// black box and only take the interface specification into account, not the instructions
/// themselves.&rdquo;
///
/// Since no actual assembler instructions are provided, it might seem that this function call
/// would have zero overhead after inlining. However, there are other considerations that may
/// affect performance:
///
/// - The barrier will (obviously) prevent matching on code patterns that span across the barrier.
/// This is intended.
/// - The barrier will force the compiler to schedule an actual register to hold the value
/// temporarily.
/// - The barrier will force the value into a single register, which may impair the compiler's
/// ability to perform optimizations such as auto-vectorization.
/// - Constant folding cannot proceed past a barrier.
///
/// For these reasons, optimization barriers are only used where necessary to minimize any
/// potential impact on performance, keeping rust-timing-shield zero-cost for as many applications
/// as possible.
#[inline(always)]
pub fn optimization_barrier_u8(mut value: u8) -> u8 {
    unsafe {
        std::arch::asm!(
            // Rust requires us to use every register defined, so we use it inside of a comment.
            "/* optimization_barrier_u8 {unused} */",

            // Define a single input/output register called "unused".
            // The Rust compiler will perceive this as a mutation of `value`.
            unused = inout(reg_byte) value,

            // By guaranteeing more invariants we improve the compiler's ability to optimize.
            // Since the assembly block is a no-op, we easily uphold all of these invariants.
            options(pure, nomem, nostack, preserves_flags)
        );
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    quickcheck! {
        fn optimization_barrier_is_identity(value: u8) -> bool {
            optimization_barrier_u8(value) == value
        }
    }

    // TODO I would like to add a test that checks the compiled LLVM IR for `select` instructions.
    // This would help confirm that the optimization barrier is working correctly.
    //
    // According to my tests, the following function compiles to a single `select`:
    //
    //  pub fn select(cond: bool, a: u32, b: u32) -> u32 {
    //      let mask = (cond as u32) - 1;
    //
    //      (a & (!mask)) | (b & mask)
    //  }
    //
    // while this function is branchless in LLVM IR and x86_64:
    //
    //  pub fn select(cond: bool, a: u32, b: u32) -> u32 {
    //      let mask = (optimization_barrier_u8(cond as u8) as u32) - 1;
    //
    //      (a & (!mask)) | (b & mask)
    //  }
    //
    // Tested with `cargo llvm-ir` from the `cargo-asm` tool.
}
