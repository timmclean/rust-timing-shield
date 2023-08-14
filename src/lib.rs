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
mod ops;
mod ord;
mod types;
mod util;

pub use crate::cond_swap::TpCondSwap;
pub use crate::eq::TpEq;
pub use crate::ord::TpOrd;
pub use crate::types::{bool::*, numbers::*};
