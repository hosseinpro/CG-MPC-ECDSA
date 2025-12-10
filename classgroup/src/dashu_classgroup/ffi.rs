// Copyright 2018 POA Networks Ltd.
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

//! Helper functions for bignum computation using dashu (pure Rust implementation).
//! This replaces the GMP FFI bindings with pure Rust equivalents.

pub use super::super::dashu::bigint::BigInt;
use crate::dashu::sign::Sign;
use std::usize;

/// Returns `true` if `z` is negative and not zero. Otherwise, returns `false`.
#[inline]
pub fn bigint_is_negative(z: &BigInt) -> bool {
    z.sign() == super::super::dashu::sign::Sign::Negative
}

#[inline]
pub fn bigint_powm(rop: &mut BigInt, base: &BigInt, exponent: &BigInt, modulus: &BigInt) {
    *rop = base.powm(exponent, modulus);
}

#[inline]
pub fn bigint_tdiv_r(r: &mut BigInt, n: &BigInt, d: &BigInt) {
    *r = n % d;
}

/// Sets `g` to the GCD of `a` and `b`, and computes `s` and `t` such that g = s*a + t*b.
#[inline]
pub fn bigint_gcdext(gcd: &mut BigInt, s: &mut BigInt, t: &mut BigInt, a: &BigInt, b: &BigInt) {
    // Avoid dashu's gcdext path that can hit an internal division assertion for small divisors.
    // Use dashu's pure-Rust gcd for g, and compute s as the modular inverse of (a/g) mod (b/g).
    // t is not required by our callers (they overwrite it later), so set it to zero.
    let g = a.gcd(b);
    *gcd = g.clone();

    // Compute s = (a/g)^{-1} mod (b/g)
    let a1 = a / &g;
    let b1 = b / &g;
    let inv = a1.invert(&b1).expect("inverse should exist when congruence is solvable");
    *s = inv;
    *t = BigInt::zero();
}

/// Doubles `rop` in-place
#[inline]
pub fn bigint_double(rop: &mut BigInt) {
    *rop = &*rop << 1;
}

#[inline]
pub fn bigint_fdiv_qr(q: &mut BigInt, r: &mut BigInt, b: &BigInt, g: &BigInt) {
    *q = b.div_floor(g);
    *r = b.mod_floor(g);
}

#[inline]
pub fn bigint_fdiv_q_ui_self(rop: &mut BigInt, op: u64) -> u64 {
    let divisor = BigInt::from(op);
    let remainder = rop.mod_floor(&divisor);
    *rop = rop.div_floor(&divisor);
    // Return the remainder
    Into::<Option<u64>>::into(&remainder).unwrap_or(0)
}

/// Unmarshals a buffer to a `BigInt`. `buf` is interpreted as a 2's complement,
/// big-endian integer. If the buffer is empty, zero is returned.
pub fn import_obj(buf: &[u8]) -> BigInt {
    if buf.is_empty() {
        return BigInt::zero();
    }
    
    let is_negative = buf[0] & 0x80 != 0;
    
    if !is_negative {
        BigInt::from(buf)
    } else {
        // Handle negative numbers in two's complement
        let mut new_buf: Vec<u8> = buf.iter()
            .cloned()
            .skip_while(|&x| x == 0xFF)
            .collect();
        
        if new_buf.is_empty() {
            BigInt::from(-1i64)
        } else {
            for i in &mut new_buf {
                *i ^= 0xFF;
            }
            !BigInt::from(&new_buf[..])
        }
    }
}

pub fn three_gcd(rop: &mut BigInt, a: &BigInt, b: &BigInt, c: &BigInt) {
    *rop = a.gcd(b);
    *rop = rop.gcd(c);
}

#[inline]
pub fn size_in_bits(obj: &BigInt) -> usize {
    obj.bit_length()
}

#[inline]
pub fn bigint_add(rop: &mut BigInt, op1: &BigInt, op2: &BigInt) {
    *rop = op1 + op2;
}

#[inline]
pub fn bigint_mul(rop: &mut BigInt, op1: &BigInt, op2: &BigInt) {
    *rop = op1 * op2;
}

#[inline]
pub fn bigint_divexact(q: &mut BigInt, n: &BigInt, d: &BigInt) {
    *q = n / d;
}

#[inline]
pub fn bigint_mul_2exp(rop: &mut BigInt, op1: &BigInt, op2: usize) {
    *rop = op1 << op2;
}

/// Divide `n` by `d`. Round towards -∞ and place the result in `q`.
#[inline]
pub fn bigint_fdiv_q(q: &mut BigInt, n: &BigInt, d: &BigInt) {
    *q = n.div_floor(d);
}

/// Subtracts `op2` from `op1` and stores the result in `rop`.
#[inline]
pub fn bigint_sub(rop: &mut BigInt, op1: &BigInt, op2: &BigInt) {
    *rop = op1 - op2;
}

/// Exports `obj` to `v` as an array of 2's complement, big-endian bytes.
/// If `v` is too small to hold the result, returns `Err(s)`, where `s` is
/// the size needed to hold the exported version of `obj`.
pub fn export_obj(obj: &BigInt, v: &mut [u8]) -> Result<(), usize> {
    let size = size_in_bits(obj);
    
    // Special case for zero
    if size == 0 {
        return if v.is_empty() {
            Ok(())
        } else {
            // Zero needs at least 1 byte
            if v.len() >= 1 {
                v[0] = 0;
                Ok(())
            } else {
                Err(1)
            }
        };
    }

    // Check to avoid integer overflow in later operations.
    if size > usize::MAX - 8 || v.len() > usize::MAX >> 3 {
        return Err(usize::MAX);
    }

    // One additional bit is needed for the sign bit.
    let byte_len_needed = (size + 8) >> 3;
    if v.len() < byte_len_needed {
        return Err(byte_len_needed);
    }

    let is_negative = bigint_is_negative(obj);

    if is_negative {
        // Handle negative numbers in two's complement
        let obj_compl = !obj;
        let bytes: Vec<u8> = (&obj_compl).into();
        let new_byte_size = bytes.len();
        let offset = v.len().saturating_sub(new_byte_size);

        // Fill leading bytes with 0xFF
        for i in &mut v[..offset] {
            *i = 0xFF;
        }

        // Copy the data
        let copy_len = new_byte_size.min(v.len() - offset);
        v[offset..offset + copy_len].copy_from_slice(&bytes[..copy_len]);

        // Flip all bits back (completing two's complement)
        for i in &mut v[offset..] {
            *i ^= 0xFF;
        }
    } else {
        let bytes: Vec<u8> = obj.into();
        let byte_len = bytes.len();
        let offset = v.len().saturating_sub(byte_len);

        // Zero out any leading bytes
        for i in &mut v[..offset] {
            *i = 0;
        }

        // Copy the data
        let copy_len = byte_len.min(v.len() - offset);
        v[offset..offset + copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    Ok(())
}

pub fn bigint_crem_u16(n: &BigInt, modulus: u16) -> u16 {
    let m = BigInt::from(modulus as u64);
    // Ceiling division remainder: rounds quotient toward positive infinity
    // r = n - ceil(n/m) * m
    let _q = n / &m;  // truncated division
    let r = n % &m;
    
    // If remainder is non-zero and positive, need to round up
    let rem = if !r.is_zero() && n.sign() == Sign::Positive {
        &r - &m  // This will be negative
    } else {
        r
    };
    
    let abs_rem = rem.abs();
    Into::<Option<u64>>::into(&abs_rem).unwrap_or(0) as u16
}

pub fn bigint_frem_u32(n: &BigInt, modulus: u32) -> u32 {
    let m = BigInt::from(modulus as u64);
    let rem = n.mod_floor(&m);
    Into::<Option<u64>>::into(&rem).unwrap_or(0) as u32
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_expected_bit_width() {
        let mut s: BigInt = (-2).into();
        assert_eq!(size_in_bits(&s), 2);
        s = !s;
        assert_eq!(s, 1.into());
        s.setbit(2);
        assert_eq!(s, 5.into());
    }

    #[test]
    fn check_export() {
        let mut s: BigInt = 0x100.into();
        s = !s;
        let mut buf = [0, 0, 0];
        export_obj(&s, &mut buf).expect("buffer should be large enough");
        assert_eq!(buf, [0xFF, 0xFE, 0xFF]);
        export_obj(&BigInt::zero(), &mut []).unwrap();
    }

    #[test]
    fn check_rem() {
        assert_eq!(bigint_crem_u16(&(-100i64).into(), 3), 1);
        assert_eq!(bigint_crem_u16(&(100i64).into(), 3), 2);
    }
}
