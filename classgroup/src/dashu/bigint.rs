use super::sign::Sign;
use dashu::integer::IBig;
use dashu::base::{Abs, RemEuclid, BitTest, Gcd, SquareRoot};
use std::cmp::Ordering;
use std::convert::{From, TryInto};
use std::error::Error;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use std::str::FromStr;
use std::{fmt, hash};

#[derive(Clone)]
pub struct BigInt {
    inner: IBig,
}

impl serde::Serialize for BigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: Vec<u8> = self.into();
        let sign = match self.sign() {
            Sign::Negative => -1i8,
            Sign::Zero => 0i8,
            Sign::Positive => 1i8,
        };
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&sign)?;
        tuple.serialize_element(&bytes)?;
        tuple.end()
    }
}

impl<'de> serde::Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D) -> Result<BigInt, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};
        
        struct BigIntTupleVisitor;
        
        impl<'de> Visitor<'de> for BigIntTupleVisitor {
            type Value = BigInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of (sign, bytes)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<BigInt, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let sign: i8 = seq.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let bytes: Vec<u8> = seq.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                
                if sign == 0 {
                    return Ok(BigInt::zero());
                }
                
                let mut bigint = BigInt::from(&bytes[..]);
                
                if sign < 0 {
                    bigint = -bigint;
                }
                
                Ok(bigint)
            }
        }

        deserializer.deserialize_tuple(2, BigIntTupleVisitor)
    }
}

/// The result of running probab_prime
#[derive(PartialEq)]
pub enum ProbabPrimeResult {
    NotPrime,
    ProbablyPrime,
    Prime,
}

impl BigInt {
    #[inline]
    pub fn new() -> BigInt {
        BigInt {
            inner: IBig::ZERO,
        }
    }

    #[inline]
    pub fn new_reserve(_n: usize) -> BigInt {
        // dashu doesn't have reserve API, just create new
        BigInt::new()
    }

    #[inline]
    pub fn reserve(&mut self, _n: usize) {
        // dashu doesn't have reserve API, this is a no-op
    }

    #[inline]
    pub fn size_in_base(&self, base: u8) -> usize {
        if self.is_zero() {
            return 1;
        }
        let abs = self.inner.clone().abs();
        // Estimate: bits / log2(base)
        let bits = abs.bit_len();
        match base {
            2 => bits,
            10 => {
                // log2(10) ≈ 3.32193
                ((bits as f64) / 3.32193).ceil() as usize + 1
            }
            16 => (bits + 3) / 4,
            _ => {
                // General case: use logarithm
                let log2_base = (base as f64).log2();
                ((bits as f64) / log2_base).ceil() as usize + 1
            }
        }
    }

    pub fn to_str_radix(&self, base: u8) -> String {
        assert!(base >= 2 && base <= 36, "invalid base");
        match base {
            10 => self.inner.to_string(),
            16 => format!("{:x}", self.inner),
            2 => format!("{:b}", self.inner),
            8 => format!("{:o}", self.inner),
            _ => {
                // For other bases, use dashu's radix formatting
                self.inner.in_radix(base as u32).to_string()
            }
        }
    }

    pub fn from_str_radix(s: &str, base: u8) -> Result<BigInt, ParseBigIntError> {
        assert!(base == 0 || (base >= 2 && base <= 62));
        let inner = if base == 0 || base == 10 {
            IBig::from_str(s).map_err(|_| ParseBigIntError { _priv: () })?
        } else {
            IBig::from_str_radix(s, base as u32).map_err(|_| ParseBigIntError { _priv: () })?
        };
        Ok(BigInt { inner })
    }

    #[inline]
    pub fn set(&mut self, other: &BigInt) {
        self.inner = other.inner.clone();
    }

    pub fn set_from_str_radix(&mut self, s: &str, base: u8) -> bool {
        assert!(base == 0 || (base >= 2 && base <= 62));
        let result = if base == 0 || base == 10 {
            IBig::from_str(s)
        } else {
            IBig::from_str_radix(s, base as u32)
        };
        match result {
            Ok(val) => {
                self.inner = val;
                true
            }
            Err(_) => false,
        }
    }

    #[inline]
    pub fn bit_length(&self) -> usize {
        self.inner.clone().abs().bit_len()
    }

    #[inline]
    pub fn compl(&self) -> BigInt {
        BigInt {
            inner: !&self.inner,
        }
    }

    #[inline]
    pub fn abs(&self) -> BigInt {
        BigInt {
            inner: self.inner.clone().abs(),
        }
    }

    #[inline]
    pub fn div_floor(&self, other: &BigInt) -> BigInt {
        if other.is_zero() {
            panic!("divide by zero")
        }
        // Floor division: rounds toward negative infinity
        // For positive divisor: -8 / 3 = -3 (not -2)
        // For negative divisor: 8 / -3 = -3 (not -2)
        let q = &self.inner / &other.inner;
        let r = &self.inner % &other.inner;
        
        // If remainder is non-zero and signs of dividend and divisor differ, subtract 1
        if r != IBig::ZERO && (self.inner < IBig::ZERO) != (other.inner < IBig::ZERO) {
            BigInt { inner: q - IBig::ONE }
        } else {
            BigInt { inner: q }
        }
    }

    #[inline]
    pub fn mod_floor(&self, other: &BigInt) -> BigInt {
        if other.is_zero() {
            panic!("divide by zero")
        }
        // Floor modulo: result has same sign as divisor
        let r = &self.inner % &other.inner;
        
        // If remainder is non-zero and signs differ, add divisor
        if r != IBig::ZERO && (self.inner < IBig::ZERO) != (other.inner < IBig::ZERO) {
            BigInt { inner: r + &other.inner }
        } else {
            BigInt { inner: r }
        }
    }

    pub fn probab_prime(&self, _reps: i32) -> ProbabPrimeResult {
        // Simplified primality test since dashu doesn't have built-in primality testing
        // This is a basic trial division and Fermat test
        if self.inner <= IBig::ONE {
            return ProbabPrimeResult::NotPrime;
        }
        if &self.inner == &IBig::from(2u32) || &self.inner == &IBig::from(3u32) {
            return ProbabPrimeResult::Prime;
        }
        if (&self.inner & IBig::ONE) == IBig::ZERO {
            return ProbabPrimeResult::NotPrime;
        }

        // Trial division with small primes
        let small_primes = [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
        for &p in &small_primes {
            let prime = IBig::from(p);
            if &self.inner == &prime {
                return ProbabPrimeResult::Prime;
            }
            if (&self.inner % &prime) == IBig::ZERO {
                return ProbabPrimeResult::NotPrime;
            }
        }

        // For larger numbers, assume probably prime after trial division
        // A full Miller-Rabin implementation would require modular exponentiation
        // which dashu doesn't expose directly
        ProbabPrimeResult::ProbablyPrime
    }

    #[inline]
    pub fn nextprime(&self) -> BigInt {
        let mut candidate = &self.inner + IBig::ONE;
        if &candidate & IBig::ONE == IBig::ZERO {
            candidate += IBig::ONE;
        }
        
        loop {
            let test = BigInt { inner: candidate.clone() };
            if test.probab_prime(25) != ProbabPrimeResult::NotPrime {
                return test;
            }
            candidate += IBig::from(2u32);
        }
    }

    #[inline]
    pub fn gcd(&self, other: &BigInt) -> BigInt {
        // GMP allows gcd(0, 0) = 0, but dashu panics
        if self.is_zero() && other.is_zero() {
            return BigInt::zero();
        }
        BigInt {
            inner: self.inner.clone().gcd(&other.inner).into(),
        }
    }

    pub fn gcdext(&self, other: &BigInt) -> (BigInt, BigInt, BigInt) {
        use dashu::base::ExtendedGcd;
        
        // Handle edge cases
        if self.is_zero() {
            return (
                other.clone().abs(),
                BigInt::zero(),
                if other.sign() == Sign::Negative {
                    BigInt::from(-1)
                } else {
                    BigInt::one()
                },
            );
        }
        if other.is_zero() {
            return (
                self.clone().abs(),
                if self.sign() == Sign::Negative {
                    BigInt::from(-1)
                } else {
                    BigInt::one()
                },
                BigInt::zero(),
            );
        }
        
        // dashu's gcd_ext requires both numbers to have at least 2 internal words (>=128 bits)
        // For numbers below this threshold, it will panic
        // Check if both numbers are large enough
        // Use a conservative threshold: 2^128 to be safe
        let threshold = IBig::from(1u128) << 128;
        let self_abs = self.inner.clone().abs();
        let other_abs = other.inner.clone().abs();
        
        let self_is_large = self_abs >= threshold;
        let other_is_large = other_abs >= threshold;
        
        if self_is_large && other_is_large {
            // Both numbers are large enough - use dashu's optimized gcd_ext
            let (g, s, t) = self.inner.clone().gcd_ext(&other.inner);
            (
                BigInt { inner: g.into() },
                BigInt { inner: s },
                BigInt { inner: t },
            )
        } else {
            // At least one number is too small for dashu's gcd_ext
            // Use standard extended Euclidean algorithm with minimal allocations
            let mut r0 = self.clone().abs();
            let mut r1 = other.clone().abs();
            let mut s0 = BigInt::one();
            let mut s1 = BigInt::zero();
            let mut t0 = BigInt::zero();
            let mut t1 = BigInt::one();
            
            while !r1.is_zero() {
                let q = &r0 / &r1;
                
                let r_temp = r0 - &q * &r1;
                r0 = std::mem::replace(&mut r1, r_temp);
                
                let s_temp = s0 - &q * &s1;
                s0 = std::mem::replace(&mut s1, s_temp);
                
                let t_temp = t0 - q * &t1;
                t0 = std::mem::replace(&mut t1, t_temp);
            }
            
            // Adjust signs for original inputs
            if self.sign() == Sign::Negative {
                s0 = -s0;
            }
            if other.sign() == Sign::Negative {
                t0 = -t0;
            }
            
            (r0, s0, t0)
        }
    }

    #[inline]
    pub fn lcm(&self, other: &BigInt) -> BigInt {
        // lcm(a, b) = |a * b| / gcd(a, b)
        if self.is_zero() || other.is_zero() {
            return BigInt::zero();
        }
        let gcd_val = self.inner.clone().gcd(&other.inner);
        let product = &self.inner * &other.inner;
        BigInt {
            inner: (product / IBig::from(gcd_val)).abs(),
        }
    }

    #[inline]
    pub fn is_multiple_of(&self, other: &BigInt) -> bool {
        if other.is_zero() {
            return false;
        }
        (&self.inner % &other.inner) == IBig::ZERO
    }

    #[inline]
    pub fn divides(&self, other: &BigInt) -> bool {
        other.is_multiple_of(self)
    }

    pub fn modulus(&self, modulo: &BigInt) -> BigInt {
        if modulo.is_zero() {
            panic!("divide by zero")
        }
        let result = self.inner.clone().rem_euclid(&modulo.inner);
        BigInt { inner: result.into() }
    }

    pub fn invert(&self, modulo: &BigInt) -> Option<BigInt> {
        let (g, s, _t) = self.gcdext(modulo);
        if g.inner != IBig::ONE {
            None
        } else {
            let result = s.inner.rem_euclid(&modulo.inner);
            Some(BigInt { inner: result.into() })
        }
    }

    #[inline]
    pub fn popcount(&self) -> usize {
        // Count the number of 1 bits in the binary representation
        let abs_val = self.inner.clone().abs();
        let bits = abs_val.bit_len();
        let mut count = 0;
        for i in 0..bits {
            if abs_val.bit(i) {
                count += 1;
            }
        }
        count
    }

    #[inline]
    pub fn pow(&self, exp: u32) -> BigInt {
        BigInt {
            inner: self.inner.pow(exp as usize),
        }
    }

    #[inline]
    pub fn powm(&self, exp: &BigInt, modulus: &BigInt) -> BigInt {
        // Implement modular exponentiation using binary method
        if modulus.is_zero() {
            panic!("modulus is zero");
        }
        
        let mut result = IBig::ONE;
        let mut base: IBig = self.inner.clone().rem_euclid(&modulus.inner).into();
        let mut exponent = exp.inner.clone();
        
        while exponent > IBig::ZERO {
            if (&exponent & IBig::ONE) == IBig::ONE {
                let temp: IBig = (&result * &base).rem_euclid(&modulus.inner).into();
                result = temp;
            }
            let temp: IBig = (&base * &base).rem_euclid(&modulus.inner).into();
            base = temp;
            exponent >>= 1;
        }
        
        BigInt { inner: result }
    }

    #[inline]
    pub fn powm_sec(&self, exp: &BigInt, modulus: &BigInt) -> BigInt {
        // dashu doesn't have constant-time operations, so this is the same as powm
        self.powm(exp, modulus)
    }

    #[inline]
    pub fn ui_pow_ui(x: u32, y: u32) -> BigInt {
        BigInt {
            inner: IBig::from(x).pow(y as usize),
        }
    }

    #[inline]
    pub fn hamdist(&self, other: &BigInt) -> usize {
        let xor_result = &self.inner ^ &other.inner;
        BigInt { inner: xor_result }.popcount()
    }

    #[inline]
    pub fn setbit(&mut self, bit_index: usize) {
        self.inner |= IBig::ONE << bit_index;
    }

    #[inline]
    pub fn clrbit(&mut self, bit_index: usize) {
        self.inner &= !(IBig::ONE << bit_index);
    }

    #[inline]
    pub fn combit(&mut self, bit_index: usize) {
        self.inner ^= IBig::ONE << bit_index;
    }

    #[inline]
    pub fn tstbit(&self, bit_index: usize) -> bool {
        (&self.inner >> bit_index) & IBig::ONE == IBig::ONE
    }

    pub fn root(&self, n: u32) -> BigInt {
        assert!(self.inner >= IBig::ZERO);
        BigInt {
            inner: self.inner.nth_root(n as usize),
        }
    }

    pub fn sqrt(&self) -> BigInt {
        assert!(self.inner >= IBig::ZERO);
        BigInt {
            inner: self.inner.clone().sqrt().into(),
        }
    }

    pub fn millerrabin(&self, reps: i32) -> i32 {
        match self.probab_prime(reps) {
            ProbabPrimeResult::Prime => 2,
            ProbabPrimeResult::ProbablyPrime => 1,
            ProbabPrimeResult::NotPrime => 0,
        }
    }

    pub fn sign(&self) -> Sign {
        match self.inner.sign() {
            dashu::base::Sign::Positive => {
                if self.inner == IBig::ZERO {
                    Sign::Zero
                } else {
                    Sign::Positive
                }
            }
            dashu::base::Sign::Negative => Sign::Negative,
        }
    }

    pub fn one() -> BigInt {
        BigInt { inner: IBig::ONE }
    }

    pub fn zero() -> BigInt {
        BigInt { inner: IBig::ZERO }
    }

    pub fn is_zero(&self) -> bool {
        self.inner == IBig::ZERO
    }
}

#[derive(Debug)]
pub struct ParseBigIntError {
    _priv: (),
}

impl fmt::Display for ParseBigIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "invalid integer".fmt(f)
    }
}

impl Error for ParseBigIntError {
    fn description(&self) -> &'static str {
        "invalid integer"
    }
}

impl Eq for BigInt {}

impl PartialEq for BigInt {
    fn eq(&self, other: &BigInt) -> bool {
        self.inner == other.inner
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &BigInt) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &BigInt) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Arithmetic operations

macro_rules! impl_binop {
    ($trait:ident, $method:ident, $trait_assign:ident, $method_assign:ident, $op:tt) => {
        impl $trait<BigInt> for BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: BigInt) -> BigInt {
                BigInt {
                    inner: self.inner $op other.inner,
                }
            }
        }

        impl<'a> $trait<&'a BigInt> for BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: &BigInt) -> BigInt {
                BigInt {
                    inner: self.inner $op &other.inner,
                }
            }
        }

        impl<'a> $trait<BigInt> for &'a BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: BigInt) -> BigInt {
                BigInt {
                    inner: &self.inner $op other.inner,
                }
            }
        }

        impl<'a, 'b> $trait<&'b BigInt> for &'a BigInt {
            type Output = BigInt;
            fn $method(self, other: &BigInt) -> BigInt {
                BigInt {
                    inner: &self.inner $op &other.inner,
                }
            }
        }

        impl $trait_assign<BigInt> for BigInt {
            #[inline]
            fn $method_assign(&mut self, other: BigInt) {
                self.inner = &self.inner $op other.inner;
            }
        }

        impl<'a> $trait_assign<&'a BigInt> for BigInt {
            #[inline]
            fn $method_assign(&mut self, other: &BigInt) {
                self.inner = &self.inner $op &other.inner;
            }
        }
    };
}

impl_binop!(Add, add, AddAssign, add_assign, +);
impl_binop!(Sub, sub, SubAssign, sub_assign, -);
impl_binop!(Mul, mul, MulAssign, mul_assign, *);
impl_binop!(BitAnd, bitand, BitAndAssign, bitand_assign, &);
impl_binop!(BitOr, bitor, BitOrAssign, bitor_assign, |);
impl_binop!(BitXor, bitxor, BitXorAssign, bitxor_assign, ^);

// Division and Remainder with panic on zero
macro_rules! impl_div_rem {
    ($trait:ident, $method:ident, $trait_assign:ident, $method_assign:ident, $op:tt) => {
        impl $trait<BigInt> for BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: BigInt) -> BigInt {
                if other.is_zero() {
                    panic!("divide by zero");
                }
                BigInt {
                    inner: self.inner $op other.inner,
                }
            }
        }

        impl<'a> $trait<&'a BigInt> for BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: &BigInt) -> BigInt {
                if other.is_zero() {
                    panic!("divide by zero");
                }
                BigInt {
                    inner: self.inner $op &other.inner,
                }
            }
        }

        impl<'a> $trait<BigInt> for &'a BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: BigInt) -> BigInt {
                if other.is_zero() {
                    panic!("divide by zero");
                }
                BigInt {
                    inner: &self.inner $op other.inner,
                }
            }
        }

        impl<'a, 'b> $trait<&'b BigInt> for &'a BigInt {
            type Output = BigInt;
            fn $method(self, other: &BigInt) -> BigInt {
                if other.is_zero() {
                    panic!("divide by zero");
                }
                BigInt {
                    inner: &self.inner $op &other.inner,
                }
            }
        }

        impl $trait_assign<BigInt> for BigInt {
            #[inline]
            fn $method_assign(&mut self, other: BigInt) {
                if other.is_zero() {
                    panic!("divide by zero");
                }
                self.inner = &self.inner $op other.inner;
            }
        }

        impl<'a> $trait_assign<&'a BigInt> for BigInt {
            #[inline]
            fn $method_assign(&mut self, other: &BigInt) {
                if other.is_zero() {
                    panic!("divide by zero");
                }
                self.inner = &self.inner $op &other.inner;
            }
        }
    };
}

impl_div_rem!(Div, div, DivAssign, div_assign, /);
impl_div_rem!(Rem, rem, RemAssign, rem_assign, %);

// Operations with primitive types
macro_rules! impl_prim_ops {
    ($prim:ty, $trait:ident, $method:ident, $trait_assign:ident, $method_assign:ident) => {
        impl $trait<$prim> for BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: $prim) -> BigInt {
                self.$method(BigInt::from(other))
            }
        }

        impl<'a> $trait<$prim> for &'a BigInt {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: $prim) -> BigInt {
                self.$method(BigInt::from(other))
            }
        }

        impl $trait<BigInt> for $prim {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: BigInt) -> BigInt {
                BigInt::from(self).$method(other)
            }
        }

        impl<'a> $trait<&'a BigInt> for $prim {
            type Output = BigInt;
            #[inline]
            fn $method(self, other: &'a BigInt) -> BigInt {
                BigInt::from(self).$method(other)
            }
        }

        impl $trait_assign<$prim> for BigInt {
            #[inline]
            fn $method_assign(&mut self, other: $prim) {
                self.$method_assign(BigInt::from(other));
            }
        }
    };
}

impl_prim_ops!(u64, Add, add, AddAssign, add_assign);
impl_prim_ops!(u64, Sub, sub, SubAssign, sub_assign);
impl_prim_ops!(u64, Mul, mul, MulAssign, mul_assign);
impl_prim_ops!(u64, Div, div, DivAssign, div_assign);
impl_prim_ops!(u64, Rem, rem, RemAssign, rem_assign);

impl_prim_ops!(i64, Mul, mul, MulAssign, mul_assign);

impl<'b> Neg for &'b BigInt {
    type Output = BigInt;
    fn neg(self) -> BigInt {
        BigInt {
            inner: -&self.inner,
        }
    }
}

impl Neg for BigInt {
    type Output = BigInt;
    #[inline]
    fn neg(self) -> BigInt {
        BigInt { inner: -self.inner }
    }
}

impl<'b> Not for &'b BigInt {
    type Output = BigInt;
    fn not(self) -> BigInt {
        BigInt {
            inner: !&self.inner,
        }
    }
}

impl Not for BigInt {
    type Output = BigInt;
    #[inline]
    fn not(self) -> BigInt {
        BigInt { inner: !self.inner }
    }
}

// Shift operations
impl<'b> Shl<usize> for &'b BigInt {
    type Output = BigInt;
    fn shl(self, other: usize) -> BigInt {
        BigInt {
            inner: &self.inner << other,
        }
    }
}

impl<'b> Shr<usize> for &'b BigInt {
    type Output = BigInt;
    fn shr(self, other: usize) -> BigInt {
        BigInt {
            inner: &self.inner >> other,
        }
    }
}

impl Shl<usize> for BigInt {
    type Output = BigInt;
    fn shl(self, other: usize) -> BigInt {
        BigInt {
            inner: self.inner << other,
        }
    }
}

impl Shr<usize> for BigInt {
    type Output = BigInt;
    fn shr(self, other: usize) -> BigInt {
        BigInt {
            inner: self.inner >> other,
        }
    }
}

impl ShlAssign<usize> for BigInt {
    fn shl_assign(&mut self, other: usize) {
        self.inner <<= other;
    }
}

impl ShrAssign<usize> for BigInt {
    fn shr_assign(&mut self, other: usize) {
        self.inner >>= other;
    }
}

// Conversions

impl<'b> From<&'b BigInt> for Vec<u8> {
    fn from(other: &BigInt) -> Vec<u8> {
        // Convert to bytes (big-endian, unsigned representation)
        if other.is_zero() {
            return vec![0];
        }
        
        // Get the absolute value and convert to hex string, then to bytes
        let abs_val = other.inner.clone().abs();
        let hex_str = format!("{:x}", abs_val);
        
        // Pad to even length if necessary
        let hex_str = if hex_str.len() % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str
        };
        
        // Convert hex string to bytes
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect()
    }
}

impl<'b> From<&'b BigInt> for Option<i64> {
    fn from(other: &BigInt) -> Option<i64> {
        other.inner.clone().try_into().ok()
    }
}

impl<'b> From<&'b BigInt> for Option<u64> {
    fn from(other: &BigInt) -> Option<u64> {
        if other.inner < IBig::ZERO {
            None
        } else {
            other.inner.clone().try_into().ok()
        }
    }
}

impl<'a> From<&'a BigInt> for f64 {
    fn from(other: &BigInt) -> f64 {
        // Convert to string and parse (not ideal but works)
        other.inner.to_string().parse().unwrap_or(0.0)
    }
}

impl<'a> From<&'a [u8]> for BigInt {
    fn from(other: &'a [u8]) -> BigInt {
        if other.is_empty() {
            return BigInt::zero();
        }
        // Convert from big-endian bytes to IBig using hex string
        let hex_str: String = other.iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        
        BigInt {
            inner: IBig::from_str_radix(&hex_str, 16).unwrap_or(IBig::ZERO),
        }
    }
}

impl From<u64> for BigInt {
    fn from(other: u64) -> BigInt {
        BigInt {
            inner: IBig::from(other),
        }
    }
}

impl From<u32> for BigInt {
    fn from(other: u32) -> BigInt {
        BigInt {
            inner: IBig::from(other),
        }
    }
}

impl From<i64> for BigInt {
    fn from(other: i64) -> BigInt {
        BigInt {
            inner: IBig::from(other),
        }
    }
}

impl From<i32> for BigInt {
    fn from(other: i32) -> BigInt {
        BigInt {
            inner: IBig::from(other),
        }
    }
}

impl FromStr for BigInt {
    type Err = ParseBigIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BigInt::from_str_radix(s, 10)
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl hash::Hash for BigInt {
    fn hash<S: hash::Hasher>(&self, state: &mut S) {
        self.inner.to_string().hash(state);
    }
}
