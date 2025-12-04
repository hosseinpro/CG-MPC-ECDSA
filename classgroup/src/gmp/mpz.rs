extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;
use core::convert::From;
use core::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use core::str::FromStr;
use core::{fmt, hash};

use num_bigint::{BigInt, Sign as NumSign};
use num_traits::{One, Zero, Signed, ToPrimitive, Num};
use num_integer::Integer as IntegerTrait;
use serde::de;
use serde::de::Visitor;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};

use super::sign::Sign;

/// Arbitrary precision integer, compatible with GMP's Mpz API
/// Now using num-bigint for dynamic allocation and better performance
#[derive(Clone, Debug)]
pub struct Mpz {
    inner: BigInt,
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
        Mpz { inner: BigInt::zero() }
    }

    pub fn from_str_radix(s: &str, radix: u8) -> Result<Self, &'static str> {
        if radix < 2 || radix > 36 {
            return Err("radix must be between 2 and 36");
        }
        
        let s = s.trim();
        if s.is_empty() {
            return Err("empty string");
        }

        BigInt::from_str_radix(s, radix as u32)
            .map(|inner| Mpz { inner })
            .map_err(|_| "failed to parse number")
    }

    pub fn to_str_radix(&self, radix: u8) -> String {
        if radix < 2 || radix > 36 {
            panic!("radix must be between 2 and 36");
        }
        self.inner.to_str_radix(radix as u32)
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
            inner: self.inner.abs(),
        }
    }

    pub fn bit_length(&self) -> usize {
        self.inner.bits() as usize
    }

    pub fn tstbit(&self, bit_index: usize) -> bool {
        self.inner.bit(bit_index as u64)
    }

    pub fn setbit(&mut self, bit_index: usize) {
        self.inner.set_bit(bit_index as u64, true);
    }

    pub fn clrbit(&mut self, bit_index: usize) {
        self.inner.set_bit(bit_index as u64, false);
    }

    pub fn combit(&mut self, bit_index: usize) {
        let current = self.tstbit(bit_index);
        self.inner.set_bit(bit_index as u64, !current);
    }
}

// Sign-related methods
impl Mpz {
    pub fn sign(&self) -> Sign {
        match self.inner.sign() {
            NumSign::NoSign => Sign::Zero,
            NumSign::Plus => Sign::Positive,
            NumSign::Minus => Sign::Negative,
        }
    }
}

// Arithmetic methods
impl Mpz {
    pub fn modulus(&self, modulo: &Mpz) -> Mpz {
        if modulo.is_zero() {
            panic!("divide by zero");
        }

        let result = &self.inner % &modulo.inner;
        
        // Ensure non-negative result
        let result = if result.sign() == NumSign::Minus {
            result + &modulo.inner
        } else {
            result
        };

        Mpz { inner: result }
    }

    pub fn div_floor(&self, other: &Mpz) -> Mpz {
        if other.is_zero() {
            panic!("divide by zero");
        }
        Mpz {
            inner: self.inner.div_floor(&other.inner),
        }
    }

    pub fn mod_floor(&self, other: &Mpz) -> Mpz {
        if other.is_zero() {
            panic!("divide by zero");
        }
        Mpz {
            inner: self.inner.mod_floor(&other.inner),
        }
    }

    pub fn gcd(&self, other: &Mpz) -> Mpz {
        Mpz {
            inner: self.inner.gcd(&other.inner),
        }
    }

    pub fn gcdext(&self, other: &Mpz) -> (Mpz, Mpz, Mpz) {
        let extended_gcd = self.inner.extended_gcd(&other.inner);
        
        (
            Mpz { inner: extended_gcd.gcd },
            Mpz { inner: extended_gcd.x },
            Mpz { inner: extended_gcd.y },
        )
    }

    pub fn lcm(&self, other: &Mpz) -> Mpz {
        Mpz {
            inner: self.inner.lcm(&other.inner),
        }
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

        // Use modpow from num-bigint
        let base = self.modulus(modulus);
        let result = base.inner.modpow(&exp.inner, &modulus.inner);
        
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
        Mpz {
            inner: self.inner.sqrt(),
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
            inner: BigInt::one(),
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
        self.inner.to_signed_bytes_be().hash(state);
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
        BigInt::from_str(s)
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
            inner: BigInt::from(n),
        }
    }
}

impl From<u64> for Mpz {
    fn from(n: u64) -> Self {
        Mpz {
            inner: BigInt::from(n),
        }
    }
}

impl From<i32> for Mpz {
    fn from(n: i32) -> Self {
        Mpz {
            inner: BigInt::from(n),
        }
    }
}

impl From<u32> for Mpz {
    fn from(n: u32) -> Self {
        Mpz {
            inner: BigInt::from(n),
        }
    }
}

// Conversions to primitive types
impl From<Mpz> for Option<i64> {
    fn from(mpz: Mpz) -> Option<i64> {
        mpz.inner.to_i64()
    }
}

impl From<&Mpz> for Option<i64> {
    fn from(mpz: &Mpz) -> Option<i64> {
        mpz.inner.to_i64()
    }
}

impl From<Mpz> for Option<u64> {
    fn from(mpz: Mpz) -> Option<u64> {
        mpz.inner.to_u64()
    }
}

impl From<&Mpz> for Option<u64> {
    fn from(mpz: &Mpz) -> Option<u64> {
        mpz.inner.to_u64()
    }
}

impl From<Mpz> for f64 {
    fn from(mpz: Mpz) -> f64 {
        mpz.inner.to_f64().unwrap_or(f64::INFINITY)
    }
}

impl From<&Mpz> for f64 {
    fn from(mpz: &Mpz) -> f64 {
        mpz.inner.to_f64().unwrap_or(f64::INFINITY)
    }
}

// Byte conversions
impl From<&[u8]> for Mpz {
    fn from(bytes: &[u8]) -> Self {
        Mpz {
            inner: BigInt::from_bytes_be(NumSign::Plus, bytes),
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
        mpz.inner.to_signed_bytes_be()
    }
}

impl From<&Mpz> for Vec<u8> {
    fn from(mpz: &Mpz) -> Vec<u8> {
        mpz.inner.to_signed_bytes_be()
    }
}

// Additional operations with u64
impl Rem<u64> for Mpz {
    type Output = Mpz;
    
    fn rem(self, other: u64) -> Mpz {
        Mpz {
            inner: self.inner % other,
        }
    }
}

impl Rem<u64> for &Mpz {
    type Output = Mpz;
    
    fn rem(self, other: u64) -> Mpz {
        Mpz {
            inner: &self.inner % other,
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
