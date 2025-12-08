#![warn(deprecated)]
#![allow(non_camel_case_types)]

extern crate libc;

mod ffi;
pub mod mpz;
pub mod sign;

#[cfg(test)]
mod test;
