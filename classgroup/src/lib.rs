// Copyright 2018 Chia Network Inc and POA Networks Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![deny(unsafe_code)]
use std::ops::{Mul, MulAssign, Rem, ShlAssign};

pub mod dashu;

pub mod dashu_classgroup;
pub use self::dashu_classgroup::{
    do_compute,
    ffi::{export_obj, import_obj},
};
pub trait BigNum:
    Clone
    + PartialOrd
    + std::fmt::Debug
    + Rem
    + ShlAssign<usize>
    + for<'a> MulAssign<&'a Self>
    + std::ops::Sub<u64, Output = Self>
    + std::ops::Add<u64, Output = Self>
    + std::convert::From<u64>
    + for<'a> std::convert::From<&'a [u8]>
    + std::ops::Shl<usize, Output = Self>
    + std::ops::Shr<usize, Output = Self>
    + std::ops::Neg<Output = Self>
    + std::str::FromStr
    + for<'a> std::ops::Div<&'a Self, Output = Self>
    + Eq
    + std::hash::Hash
{
    fn one() -> Self;
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
    fn probab_prime(&self, iterations: u32) -> bool;
    fn setbit(&mut self, offset: usize);
    fn mod_powm(&mut self, base: &Self, exponent: &Self, modulus: &Self);
}

pub trait BigNumExt: BigNum {
    fn frem_u32(&self, modulus: u32) -> u32;
    fn crem_u16(&mut self, modulus: u16) -> u16;
}

pub trait ClassGroup:
    Sized + Clone + for<'a> MulAssign<&'a Self> + for<'a> Mul<&'a Self> + PartialEq + std::fmt::Debug
{
    type BigNum: BigNum;

    /// Produces a `Self` from `a`, `b`, and a discriminant.
    fn from_ab_discriminant(a: Self::BigNum, b: Self::BigNum, discriminant: Self::BigNum) -> Self;

    /// Unmarshals a `Self` from a byte array and discriminant.
    ///
    /// The byte array will be in the format of two big-endian byte sequences
    /// concatenated together.
    fn from_bytes(bytearray: &[u8], discriminant: Self::BigNum) -> Self;

    fn to_bytes(&self) -> Vec<u8>;

    /// Computes the identity element of `Self` for a given discriminant.
    ///
    /// If the discriminant is not valid, the result is unspecified.
    ///
    /// # Panics
    ///
    /// This may panic (but is not required to) if the discriminant is not
    /// valid. If this function does not panic, the results of future
    /// operations are unspecified: they will not invoke undefined behavior,
    /// but may panic, loop forever, or just compute garbage.
    ///
    /// In debug builds, this will always panic if the discriminant is invalid.
    fn identity_for_discriminant(discriminant: Self::BigNum) -> Self {
        Self::from_ab_discriminant(Self::BigNum::one(), Self::BigNum::one(), discriminant)
    }

    /// Serializes `self` to a byte array.  Returns `Err(s)` if there
    /// is not enough space in the buffer.
    ///
    /// The data must be serialized in twos-complement, big-endian format.
    fn serialize(&self, buf: &mut [u8]) -> std::result::Result<(), usize>;

    /// Deserializes a bignum from raw bytes.  The bytes **must** be interpreted
    /// as a big-endian unsigned integer.
    fn unsigned_deserialize_bignum(_: &[u8]) -> Self::BigNum;

    /// Reduce `self` in-place.
    fn reduce(&mut self);

    /// Squares `self`, modifying it in-place.
    ///
    /// A default implementation is provided, but implementations are suggested
    /// to override it for performance reasons.
    fn square(&mut self) {
        let s = self.clone();
        self.mul_assign(&s)
    }

    /// Normalize `self`.
    fn normalize(&mut self);

    /// The length of `num` in **bits**
    fn size_in_bits(num: &Self::BigNum) -> usize;

    /// Gets the discriminant of `self`.
    fn discriminant(&self) -> &Self::BigNum;

    /// Computes the identity element of a `ClassGroup`.
    fn identity(&self) -> Self {
        Self::identity_for_discriminant(self.discriminant().clone())
    }

    /// Generates a *generator* for the class group of `Self`, given a
    /// discriminant.
    ///
    /// If the discriminant is not valid, the result is unspecified.
    ///
    /// # Relation to `Self::identity_for_discriminant`
    ///
    /// This is *not* the same as `Self::identity_for_discriminant`: the
    /// identity element is *never* a generator for *any* group.  This follows
    /// from their definitions: the identity element, when multiplied by another
    /// element, always gives that other element, whereas *every* element in the
    /// group is some power of a generator.
    ///
    /// # Panics
    ///
    /// This may panic (but is not required to) if the discriminant is not
    /// valid. If this function does not panic, the results of future
    /// operations are unspecified: they will not invoke undefined behavior,
    /// but may panic, loop forever, or just compute garbage.
    ///
    /// If the global allocator panics on running out of memory, then this
    /// function may panic in the same situation, but it may also just abort the
    /// program instead.
    ///
    /// In debug builds, this will always panic if the discriminant is invalid.
    fn generator_for_discriminant(discriminant: Self::BigNum) -> Self {
        Self::from_ab_discriminant(2.into(), Self::BigNum::one(), discriminant)
    }

    /// Replaces `*self` with its inverse.
    fn inverse(&mut self);

    /// Squares `self` repeatedly in-place.
    ///
    /// Implementors of this trait are encouraged to override this
    /// with a more efficient implementation, if one exists.
    fn repeated_square(&mut self, iterations: u64) {
        for _ in 0..iterations {
            self.square()
        }
    }

    /// Exponentiation
    fn pow(&mut self, exponent: Self::BigNum);

    /// Deserialization
    fn deserialize(buf: &[u8], discriminant: Self::BigNum) -> Self;
}
