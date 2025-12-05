extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;
use core::convert::{From, TryInto};
use core::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use core::str::FromStr;
use core::{fmt, hash};

use dashu_int::{IBig, Sign, UBig};
use dashu_int::ops::{Abs, BitTest, Gcd, SquareRoot, DivEuclid, RemEuclid};
use num_traits::{One, Zero, ToPrimitive};
use serde::de;
use serde::de::Visitor;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};

/// Arbitrary precision integer, compatible with GMP's Mpz API
/// Now using dashu-int for dynamic allocation and better performance
#[derive(Clone, Debug)]
pub struct Mpz {
    inner: IBig,
}

const HEX_RADIX: u8 = 16;

impl Serialize for Mpz {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str_radix(HEX_RADIX))
    }
}

struct MpzVisitor;

impl<'de> Deserialize<'de> for Mpz {
    fn deserialize<D>(deserializer: D) -> Result<Mpz, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(MpzVisitor)
    }
}

impl<'de> Visitor<'de> for MpzVisitor {
    type Value = Mpz;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string representing a hexadecimal number")
    }

    fn visit_str<E>(self, value: &str) -> Result<Mpz, E>
    where
        E: de::Error,
    {
        Mpz::from_str_radix(value, HEX_RADIX).map_err(de::Error::custom)
    }
}

// Constructors
impl Mpz {
    pub fn new() -> Self {
        Mpz { inner: IBig::ZERO }
    }

    pub fn from_str_radix(s: &str, radix: u8) -> Result<Self, &'static str> {
        if radix < 2 || radix > 36 {
            return Err("radix must be between 2 and 36");
        }
        
        let s = s.trim();
        if s.is_empty() {
            return Err("empty string");
        }

        IBig::from_str_radix(s, radix as u32)
            .map(|inner| Mpz { inner })
            .map_err(|_| "failed to parse number")
    }

    pub fn to_str_radix(&self, radix: u8) -> String {
        if radix < 2 || radix > 36 {
            panic!("radix must be between 2 and 36");
        }
        self.inner.in_radix(radix as u32).to_string()
    }

    pub fn set(&mut self, other: &Mpz) {
        self.inner = other.inner.clone();
    }

    pub fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    pub fn is_one(&self) -> bool {
        self.inner.is_one()
    }

    pub fn abs(&self) -> Mpz {
        Mpz {
            inner: self.inner.clone().abs(),
        }
    }

    pub fn bit_length(&self) -> usize {
        self.inner.bit_len()
    }

    pub fn tstbit(&self, bit_index: usize) -> bool {
        self.inner.bit(bit_index)
    }

    pub fn setbit(&mut self, bit_index: usize) {
        // dashu-int doesn't have mutable bit operations, so we need to use bitwise OR
        self.inner |= IBig::ONE << bit_index;
    }

    pub fn clrbit(&mut self, bit_index: usize) {
        // Clear bit by AND with NOT of the bit mask
        self.inner &= !(IBig::ONE << bit_index);
    }

    pub fn combit(&mut self, bit_index: usize) {
        // Toggle bit by XOR with the bit mask
        self.inner ^= IBig::ONE << bit_index;
    }
}

impl From<IBig> for Mpz {
    fn from(inner: IBig) -> Self {
        Mpz { inner }
    }
}

impl From<&IBig> for Mpz {
    fn from(inner: &IBig) -> Self {
        Mpz {
            inner: inner.clone(),
        }
    }
}

impl From<Mpz> for IBig {
    fn from(value: Mpz) -> Self {
        value.inner
    }
}

impl From<&Mpz> for IBig {
    fn from(value: &Mpz) -> Self {
        value.inner.clone()
    }
}

// Sign-related methods
impl Mpz {
    pub fn sign(&self) -> Sign {
        self.inner.sign()
    }
}

// Arithmetic methods
impl Mpz {
    pub fn modulus(&self, modulo: &Mpz) -> Mpz {
        if modulo.is_zero() {
            panic!("divide by zero");
        }

        // Use rem_euclid for floor modulus semantics
        Mpz {
            inner: IBig::from((&self.inner).rem_euclid(&modulo.inner)),
        }
    }

    pub fn div_floor(&self, other: &Mpz) -> Mpz {
        if other.is_zero() {
            panic!("divide by zero");
        }
        // Fast path for division by 1
        if other.is_one() {
            return self.clone();
        }
        Mpz {
            inner: (&self.inner).div_euclid(&other.inner),
        }
    }

    pub fn mod_floor(&self, other: &Mpz) -> Mpz {
        if other.is_zero() {
            panic!("divide by zero");
        }
        Mpz {
            inner: IBig::from((&self.inner).rem_euclid(&other.inner)),
        }
    }

    pub fn gcd(&self, other: &Mpz) -> Mpz {
        // Fast path for common cases
        if self.is_zero() {
            return other.abs();
        }
        if other.is_zero() {
            return self.abs();
        }
        Mpz {
            inner: IBig::from((&self.inner).gcd(&other.inner)),
        }
    }

    pub fn gcdext(&self, other: &Mpz) -> (Mpz, Mpz, Mpz) {
        // Implement extended GCD using the Euclidean algorithm
        if other.is_zero() {
            let sign = if self.inner >= IBig::ZERO { IBig::ONE } else { -IBig::ONE };
            return (self.abs(), Mpz { inner: sign }, Mpz::zero());
        }
        
        let mut old_r = self.inner.clone();
        let mut r = other.inner.clone();
        let mut old_s = IBig::ONE;
        let mut s = IBig::ZERO;
        let mut old_t = IBig::ZERO;
        let mut t = IBig::ONE;
        
        while r != IBig::ZERO {
            let quotient = &old_r / &r;
            let temp = r.clone();
            r = &old_r - &quotient * &r;
            old_r = temp;
            
            let temp = s.clone();
            s = &old_s - &quotient * &s;
            old_s = temp;
            
            let temp = t.clone();
            t = &old_t - &quotient * &t;
            old_t = temp;
        }
        
        (
            Mpz { inner: old_r },
            Mpz { inner: old_s },
            Mpz { inner: old_t },
        )
    }

    pub fn lcm(&self, other: &Mpz) -> Mpz {
        if self.is_zero() || other.is_zero() {
            return Mpz::zero();
        }
        let gcd = self.gcd(other);
        let result = (self / &gcd) * other;
        result.abs()
    }

    pub fn powm(&self, exp: &Mpz, modulus: &Mpz) -> Mpz {
        if modulus.is_zero() {
            panic!("modulus is zero");
        }
        if modulus == &Mpz::one() {
            return Mpz::zero();
        }
        if exp.is_zero() {
            return Mpz::one();
        }
        if self.is_zero() {
            return Mpz::zero();
        }

        // Handle negative exponent
        if exp.sign() == Sign::Negative {
            let inv = self.invert(modulus);
            if let Some(inv_val) = inv {
                return inv_val.powm(&(-exp), modulus);
            } else {
                panic!("base is not invertible modulo m");
            }
        }

        // Implement modular exponentiation using square and multiply
        // dashu-int doesn't have built-in modpow, so we implement it
        let mut result = IBig::ONE;
        let mut base = IBig::from((&self.inner).rem_euclid(&modulus.inner));
        let mut exp_val = exp.inner.clone();
        
        while exp_val > IBig::ZERO {
            if exp_val.bit(0) {
                result = IBig::from((result * &base).rem_euclid(&modulus.inner));
            }
            base = IBig::from((&base * &base).rem_euclid(&modulus.inner));
            exp_val >>= 1;
        }
        
        Mpz { inner: result }
    }

    pub fn invert(&self, modulus: &Mpz) -> Option<Mpz> {
        if modulus.is_zero() {
            return None;
        }

        let (gcd, x, _y) = self.gcdext(modulus);
        
        if !gcd.is_one() {
            return None;
        }

        // Ensure the result is in the range [0, modulus)
        let result = x.modulus(modulus);
        Some(result)
    }

    pub fn probab_prime(&self, _reps: i32) -> ProbabPrimeResult {
        // TODO: Implement Miller-Rabin primality test
        ProbabPrimeResult::ProbablyPrime
    }

    pub fn nextprime(&self) -> Mpz {
        // TODO: Implement
        self.clone()
    }

    pub fn root(&self, _n: u32) -> Mpz {
        // TODO: Implement nth root
        self.clone()
    }

    pub fn sqrt(&self) -> Mpz {
        if self.sign() == Sign::Negative {
            panic!("square root of negative number");
        }
        Mpz {
            inner: IBig::from(self.inner.sqrt()),
        }
    }

    pub fn millerrabin(&self, _reps: i32) -> i32 {
        // TODO: Implement Miller-Rabin test
        1
    }

    pub fn mod_powm(&mut self, base: &Self, exponent: &Self, modulus: &Self) {
        *self = base.powm(exponent, modulus);
    }

    pub fn frem_u32(&self, modulus: u32) -> u32 {
        (&self.inner % modulus).to_u32().unwrap_or(0)
    }

    pub fn crem_u16(&mut self, modulus: u16) -> u16 {
        let result = (&self.inner % modulus as u64).to_u16().unwrap_or(0);
        *self = Mpz::from(result as u64);
        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbabPrimeResult {
    NotPrime,
    ProbablyPrime,
    Prime,
}

// Trait implementations
impl Default for Mpz {
    fn default() -> Self {
        Self::new()
    }
}

impl Zero for Mpz {
    fn zero() -> Self {
        Mpz::new()
    }

    fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }
}

impl One for Mpz {
    fn one() -> Self {
        Mpz {
            inner: IBig::ONE,
        }
    }
}

impl PartialEq for Mpz {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Mpz {}

impl PartialOrd for Mpz {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Mpz {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl hash::Hash for Mpz {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        // Convert to bytes for hashing
        let bytes: Vec<u8> = self.into();
        bytes.hash(state);
    }
}

impl fmt::Display for Mpz {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for Mpz {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IBig::from_str(s)
            .map(|inner| Mpz { inner })
            .map_err(|_| "failed to parse number")
    }
}

// Arithmetic operators
impl Add for Mpz {
    type Output = Mpz;
    
    fn add(self, other: Mpz) -> Mpz {
        Mpz {
            inner: self.inner + other.inner,
        }
    }
}

impl Add for &Mpz {
    type Output = Mpz;
    
    fn add(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: &self.inner + &other.inner,
        }
    }
}

impl Add<&Mpz> for Mpz {
    type Output = Mpz;
    
    fn add(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: self.inner + &other.inner,
        }
    }
}

impl AddAssign for Mpz {
    fn add_assign(&mut self, other: Mpz) {
        self.inner += other.inner;
    }
}

impl AddAssign<&Mpz> for Mpz {
    fn add_assign(&mut self, other: &Mpz) {
        self.inner += &other.inner;
    }
}

impl Sub for Mpz {
    type Output = Mpz;
    
    fn sub(self, other: Mpz) -> Mpz {
        Mpz {
            inner: self.inner - other.inner,
        }
    }
}

impl Sub for &Mpz {
    type Output = Mpz;
    
    fn sub(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: &self.inner - &other.inner,
        }
    }
}

impl Sub<&Mpz> for Mpz {
    type Output = Mpz;
    
    fn sub(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: self.inner - &other.inner,
        }
    }
}

impl SubAssign for Mpz {
    fn sub_assign(&mut self, other: Mpz) {
        self.inner -= other.inner;
    }
}

impl SubAssign<&Mpz> for Mpz {
    fn sub_assign(&mut self, other: &Mpz) {
        self.inner -= &other.inner;
    }
}

impl Mul for Mpz {
    type Output = Mpz;
    
    fn mul(self, other: Mpz) -> Mpz {
        Mpz {
            inner: self.inner * other.inner,
        }
    }
}

impl Mul for &Mpz {
    type Output = Mpz;
    
    fn mul(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: &self.inner * &other.inner,
        }
    }
}

impl Mul<&Mpz> for Mpz {
    type Output = Mpz;
    
    fn mul(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: self.inner * &other.inner,
        }
    }
}

impl MulAssign for Mpz {
    fn mul_assign(&mut self, other: Mpz) {
        self.inner *= other.inner;
    }
}

impl MulAssign<&Mpz> for Mpz {
    fn mul_assign(&mut self, other: &Mpz) {
        self.inner *= &other.inner;
    }
}

impl Div for Mpz {
    type Output = Mpz;
    
    fn div(self, other: Mpz) -> Mpz {
        &self / &other
    }
}

impl Div<&Mpz> for Mpz {
    type Output = Mpz;
    
    fn div(self, other: &Mpz) -> Mpz {
        &self / other
    }
}

impl Div for &Mpz {
    type Output = Mpz;
    
    fn div(self, other: &Mpz) -> Mpz {
        if other.is_zero() {
            panic!("divide by zero");
        }
        Mpz {
            inner: &self.inner / &other.inner,
        }
    }
}

impl DivAssign for Mpz {
    fn div_assign(&mut self, other: Mpz) {
        if other.is_zero() {
            panic!("divide by zero");
        }
        self.inner /= other.inner;
    }
}

impl DivAssign<&Mpz> for Mpz {
    fn div_assign(&mut self, other: &Mpz) {
        if other.is_zero() {
            panic!("divide by zero");
        }
        self.inner /= &other.inner;
    }
}

impl Rem for Mpz {
    type Output = Mpz;
    
    fn rem(self, other: Mpz) -> Mpz {
        &self % &other
    }
}

impl Rem for &Mpz {
    type Output = Mpz;
    
    fn rem(self, other: &Mpz) -> Mpz {
        if other.is_zero() {
            panic!("divide by zero");
        }
        Mpz {
            inner: &self.inner % &other.inner,
        }
    }
}

impl RemAssign for Mpz {
    fn rem_assign(&mut self, other: Mpz) {
        if other.is_zero() {
            panic!("divide by zero");
        }
        self.inner %= other.inner;
    }
}

impl RemAssign<&Mpz> for Mpz {
    fn rem_assign(&mut self, other: &Mpz) {
        if other.is_zero() {
            panic!("divide by zero");
        }
        self.inner %= &other.inner;
    }
}

impl Neg for Mpz {
    type Output = Mpz;
    
    fn neg(self) -> Mpz {
        Mpz {
            inner: -self.inner,
        }
    }
}

impl Neg for &Mpz {
    type Output = Mpz;
    
    fn neg(self) -> Mpz {
        Mpz {
            inner: -&self.inner,
        }
    }
}

// Bitwise operators
impl BitAnd for Mpz {
    type Output = Mpz;
    
    fn bitand(self, other: Mpz) -> Mpz {
        Mpz {
            inner: self.inner & other.inner,
        }
    }
}

impl BitAnd for &Mpz {
    type Output = Mpz;
    
    fn bitand(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: &self.inner & &other.inner,
        }
    }
}

impl BitAndAssign for Mpz {
    fn bitand_assign(&mut self, other: Mpz) {
        self.inner &= other.inner;
    }
}

impl BitAndAssign<&Mpz> for Mpz {
    fn bitand_assign(&mut self, other: &Mpz) {
        self.inner &= &other.inner;
    }
}

impl BitOr for Mpz {
    type Output = Mpz;
    
    fn bitor(self, other: Mpz) -> Mpz {
        Mpz {
            inner: self.inner | other.inner,
        }
    }
}

impl BitOr for &Mpz {
    type Output = Mpz;
    
    fn bitor(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: &self.inner | &other.inner,
        }
    }
}

impl BitOrAssign for Mpz {
    fn bitor_assign(&mut self, other: Mpz) {
        self.inner |= other.inner;
    }
}

impl BitOrAssign<&Mpz> for Mpz {
    fn bitor_assign(&mut self, other: &Mpz) {
        self.inner |= &other.inner;
    }
}

impl BitXor for Mpz {
    type Output = Mpz;
    
    fn bitxor(self, other: Mpz) -> Mpz {
        Mpz {
            inner: self.inner ^ other.inner,
        }
    }
}

impl BitXor for &Mpz {
    type Output = Mpz;
    
    fn bitxor(self, other: &Mpz) -> Mpz {
        Mpz {
            inner: &self.inner ^ &other.inner,
        }
    }
}

impl BitXorAssign for Mpz {
    fn bitxor_assign(&mut self, other: Mpz) {
        self.inner ^= other.inner;
    }
}

impl BitXorAssign<&Mpz> for Mpz {
    fn bitxor_assign(&mut self, other: &Mpz) {
        self.inner ^= &other.inner;
    }
}

impl Not for Mpz {
    type Output = Mpz;
    
    fn not(self) -> Mpz {
        Mpz {
            inner: !self.inner,
        }
    }
}

impl Not for &Mpz {
    type Output = Mpz;
    
    fn not(self) -> Mpz {
        Mpz {
            inner: !&self.inner,
        }
    }
}

// Shift operators
impl Shl<usize> for Mpz {
    type Output = Mpz;
    
    fn shl(self, n: usize) -> Mpz {
        &self << n
    }
}

impl Shl<usize> for &Mpz {
    type Output = Mpz;
    
    fn shl(self, n: usize) -> Mpz {
        Mpz {
            inner: &self.inner << n,
        }
    }
}

impl ShlAssign<usize> for Mpz {
    fn shl_assign(&mut self, n: usize) {
        self.inner <<= n;
    }
}

impl Shr<usize> for Mpz {
    type Output = Mpz;
    
    fn shr(self, n: usize) -> Mpz {
        &self >> n
    }
}

impl Shr<usize> for &Mpz {
    type Output = Mpz;
    
    fn shr(self, n: usize) -> Mpz {
        Mpz {
            inner: &self.inner >> n,
        }
    }
}

impl ShrAssign<usize> for Mpz {
    fn shr_assign(&mut self, n: usize) {
        self.inner >>= n;
    }
}

// Conversions from primitive types
impl From<i64> for Mpz {
    fn from(n: i64) -> Self {
        Mpz {
            inner: IBig::from(n),
        }
    }
}

impl From<u64> for Mpz {
    fn from(n: u64) -> Self {
        Mpz {
            inner: IBig::from(n),
        }
    }
}

impl From<i32> for Mpz {
    fn from(n: i32) -> Self {
        Mpz {
            inner: IBig::from(n),
        }
    }
}

impl From<u32> for Mpz {
    fn from(n: u32) -> Self {
        Mpz {
            inner: IBig::from(n),
        }
    }
}

// Conversions to primitive types
impl From<Mpz> for Option<i64> {
    fn from(mpz: Mpz) -> Option<i64> {
        mpz.inner.try_into().ok()
    }
}

impl From<&Mpz> for Option<i64> {
    fn from(mpz: &Mpz) -> Option<i64> {
        mpz.inner.clone().try_into().ok()
    }
}

impl From<Mpz> for Option<u64> {
    fn from(mpz: Mpz) -> Option<u64> {
        mpz.inner.try_into().ok()
    }
}

impl From<&Mpz> for Option<u64> {
    fn from(mpz: &Mpz) -> Option<u64> {
        mpz.inner.clone().try_into().ok()
    }
}

impl From<Mpz> for f64 {
    fn from(mpz: Mpz) -> f64 {
        mpz.inner.to_f64().value()
    }
}

impl From<&Mpz> for f64 {
    fn from(mpz: &Mpz) -> f64 {
        mpz.inner.to_f64().value()
    }
}

// Byte conversions
impl From<&[u8]> for Mpz {
    fn from(bytes: &[u8]) -> Self {
        // Convert bytes (big-endian) to IBig
        let ubig = UBig::from_be_bytes(bytes);
        Mpz {
            inner: IBig::from(ubig),
        }
    }
}

impl From<Vec<u8>> for Mpz {
    fn from(bytes: Vec<u8>) -> Self {
        Mpz::from(bytes.as_slice())
    }
}

impl From<Mpz> for Vec<u8> {
    fn from(mpz: Mpz) -> Vec<u8> {
        // Convert IBig to bytes
        let (sign, ubig) = mpz.inner.into_parts();
        let mut bytes = ubig.to_be_bytes();
        
        // Handle sign for 2's complement representation
        if sign == Sign::Negative {
            // For negative numbers, we need to use 2's complement
            // This is a simplification - might need more complex handling
            for byte in bytes.iter_mut() {
                *byte = !*byte;
            }
            // Add 1 for 2's complement
            let mut carry = true;
            for byte in bytes.iter_mut().rev() {
                if carry {
                    let (new_byte, new_carry) = byte.overflowing_add(1);
                    *byte = new_byte;
                    carry = new_carry;
                }
            }
        }
        
        bytes.to_vec()
    }
}

impl From<&Mpz> for Vec<u8> {
    fn from(mpz: &Mpz) -> Vec<u8> {
        mpz.clone().into()
    }
}

// Additional operations with u64
impl Rem<u64> for Mpz {
    type Output = Mpz;
    
    fn rem(self, other: u64) -> Mpz {
        Mpz {
            inner: IBig::from(self.inner % other),
        }
    }
}

impl Rem<u64> for &Mpz {
    type Output = Mpz;
    
    fn rem(self, other: u64) -> Mpz {
        Mpz {
            inner: IBig::from(&self.inner % other),
        }
    }
}

// Additional operations for BigNum trait
impl Sub<u64> for Mpz {
    type Output = Mpz;
    
    fn sub(self, other: u64) -> Mpz {
        Mpz {
            inner: self.inner - other,
        }
    }
}

impl Add<u64> for Mpz {
    type Output = Mpz;
    
    fn add(self, other: u64) -> Mpz {
        Mpz {
            inner: self.inner + other,
        }
    }
}

// Conversions to/from num-bigint::BigInt for compatibility with multi_party_ecdsa
impl From<num_bigint::BigInt> for Mpz {
    fn from(bigint: num_bigint::BigInt) -> Self {
        let (sign, bytes) = bigint.to_bytes_be();
        let ubig = UBig::from_be_bytes(&bytes);
        let ibig = match sign {
            num_bigint::Sign::Plus | num_bigint::Sign::NoSign => IBig::from(ubig),
            num_bigint::Sign::Minus => -IBig::from(ubig),
        };
        Mpz { inner: ibig }
    }
}

impl From<&num_bigint::BigInt> for Mpz {
    fn from(bigint: &num_bigint::BigInt) -> Self {
        Mpz::from(bigint.clone())
    }
}

impl From<Mpz> for num_bigint::BigInt {
    fn from(mpz: Mpz) -> Self {
        let (sign, ubig) = mpz.inner.into_parts();
        let bytes = ubig.to_be_bytes();
        let bigint_sign = match sign {
            Sign::Positive => num_bigint::Sign::Plus,
            Sign::Negative => num_bigint::Sign::Minus,
        };
        num_bigint::BigInt::from_bytes_be(bigint_sign, &bytes)
    }
}

impl From<&Mpz> for num_bigint::BigInt {
    fn from(mpz: &Mpz) -> Self {
        mpz.clone().into()
    }
}
