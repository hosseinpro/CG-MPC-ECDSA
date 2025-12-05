extern crate alloc;
use alloc::vec::Vec;

pub use crate::mpz::Mpz;
use num_traits::{Zero};

pub fn mpz_crem_u16(n: &Mpz, d: u16) -> u16 {
    n.abs().crem_u16(d)
}

pub fn mpz_frem_u32(n: &Mpz, d: u32) -> u32 {
    n.frem_u32(d)
}

/// Returns `true` if `z` is negative and not zero.  Otherwise,
/// returns `false`.
#[inline]
pub fn mpz_is_negative(z: &Mpz) -> bool {
    use dashu_int::Sign;
    z.sign() == Sign::Negative
}

#[inline]
pub fn mpz_powm(rop: &mut Mpz, base: &Mpz, exponent: &Mpz, modulus: &Mpz) {
    *rop = base.powm(exponent, modulus);
}

#[inline]
pub fn mpz_tdiv_r(r: &mut Mpz, n: &Mpz, d: &Mpz) {
    *r = n % d;
}

/// Sets `g` to the GCD of `a` and `b`, and sets `s` and `t` such that
/// `gcd = s*a + t*b` (extended Euclidean algorithm).
#[inline]
pub fn mpz_gcdext(gcd: &mut Mpz, s: &mut Mpz, t: &mut Mpz, a: &Mpz, b: &Mpz) {
    let (g, x, y) = a.gcdext(b);
    *gcd = g;
    *s = x;
    *t = y;
}

/// Doubles `rop` in-place
#[inline(always)]
pub fn mpz_double(rop: &mut Mpz) {
    *rop = &*rop << 1;
}

#[inline]
pub fn mpz_fdiv_qr(q: &mut Mpz, r: &mut Mpz, n: &Mpz, d: &Mpz) {
    *q = n.div_floor(d);
    *r = n.mod_floor(d);
}

#[inline]
pub fn mpz_fdiv_q_ui_self(rop: &mut Mpz, op: u64) -> u64 {
    let divisor = Mpz::from(op as i64);
    let quotient = rop.div_floor(&divisor);
    let remainder_mpz = rop.mod_floor(&divisor);
    *rop = quotient;
    
    // Return the remainder as u64
    let remainder_opt: Option<i64> = remainder_mpz.into();
    remainder_opt.unwrap_or(0) as u64
}

/// Unmarshals a buffer to an `Mpz`.  `buf` is interpreted as a 2's complement,
/// big-endian integer.  If the buffer is empty, zero is returned.
pub fn import_obj(buf: &[u8]) -> Mpz {
    if buf.is_empty() {
        return Mpz::zero();
    }
    
    let is_negative = buf[0] & 0x80 != 0;
    
    if !is_negative {
        // Positive number - direct conversion
        Mpz::from(buf)
    } else {
        // Negative number in 2's complement
        // Skip leading 0xFF bytes
        let trimmed: Vec<u8> = buf.iter().cloned().skip_while(|&x| x == 0xFF).collect();
        
        if trimmed.is_empty() {
            Mpz::from(-1)
        } else {
            // Invert bits (one's complement)
            let inverted: Vec<u8> = trimmed.iter().map(|&x| x ^ 0xFF).collect();
            // Convert and then negate (bitwise NOT)
            !Mpz::from(inverted.as_slice())
        }
    }
}

pub fn three_gcd(rop: &mut Mpz, a: &Mpz, b: &Mpz, c: &Mpz) {
    // Optimize by computing gcd(gcd(a,b), c) in-place
    *rop = a.gcd(b);
    *rop = rop.gcd(c);
}

#[inline(always)]
pub fn size_in_bits(obj: &Mpz) -> usize {
    obj.bit_length()
}

#[inline(always)]
pub fn mpz_add(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    *rop = op1 + op2;
}

#[inline(always)]
pub fn mpz_mul(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    *rop = op1 * op2;
}

#[inline(always)]
pub fn mpz_divexact(q: &mut Mpz, n: &Mpz, d: &Mpz) {
    *q = n / d;
}

#[inline(always)]
pub fn mpz_mul_2exp(rop: &mut Mpz, op1: &Mpz, op2: usize) {
    *rop = op1 << op2;
}

/// Divide `n` by `d`.  Round towards -∞ and place the result in `q`.
#[inline(always)]
pub fn mpz_fdiv_q(q: &mut Mpz, n: &Mpz, d: &Mpz) {
    *q = n.div_floor(d);
}

/// In-place floor division: rop = rop / d
#[inline(always)]
pub fn mpz_fdiv_q_self(rop: &mut Mpz, d: &Mpz) {
    let tmp = rop.div_floor(d);
    *rop = tmp;
}

#[inline]
pub fn mpz_sub(rop: &mut Mpz, op1: &Mpz, op2: &Mpz) {
    *rop = op1 - op2;
}

/// In-place subtraction: rop = rop - op
#[inline]
pub fn mpz_sub_self(rop: &mut Mpz, op: &Mpz) {
    *rop -= op;
}

/// In-place addition: rop = rop + op
#[inline]
pub fn mpz_add_self(rop: &mut Mpz, op: &Mpz) {
    *rop += op;
}

/// In-place multiplication: rop = rop * op
#[inline]
pub fn mpz_mul_self(rop: &mut Mpz, op: &Mpz) {
    *rop *= op;
}

/// Exports `obj` to `v` as an array of 2's complement, big-endian
/// bytes.  If `v` is too small to hold the result, returns `Err(s)`,
/// where `s` is the size needed to hold the exported version of `obj`.
pub fn export_obj(obj: &Mpz, v: &mut [u8]) -> Result<(), usize> {
    let size = size_in_bits(obj);
    if size == 0 && v.is_empty() {
        return Ok(());
    }
    
    // Check to avoid integer overflow
    if size > usize::MAX - 8 || v.len() > usize::MAX >> 3 {
        return Err(usize::MAX);
    }
    
    // One additional bit is needed for the sign bit
    let byte_len_needed = (size + 8) >> 3;
    if v.len() < byte_len_needed {
        return if v.is_empty() && obj.is_zero() {
            Ok(())
        } else {
            Err(byte_len_needed)
        };
    }
    
    let is_negative = mpz_is_negative(obj);
    
    if is_negative {
        // For negative numbers, use 2's complement representation
        let obj_not = !obj;
        let bytes: Vec<u8> = (&obj_not).into();
        let byte_len = bytes.len();
        let offset = v.len() - byte_len;
        
        // Fill leading bytes with 0xFF
        for i in &mut v[..offset] {
            *i = 0xFF;
        }
        
        // Copy the bytes
        v[offset..].copy_from_slice(&bytes);
        
        // Invert all bits (one's complement to get back to 2's complement representation)
        for i in &mut v[offset..] {
            *i ^= 0xFF;
        }
    } else {
        // For positive numbers
        let bytes: Vec<u8> = obj.into();
        let byte_len = bytes.len();
        let offset = v.len() - byte_len;
        
        // Fill leading bytes with 0x00
        for i in &mut v[..offset] {
            *i = 0;
        }
        
        // Copy the bytes
        v[offset..].copy_from_slice(&bytes);
    }
    
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn check_expected_bit_width() {
        let s: Mpz = (-2).into();
        assert_eq!(size_in_bits(&s), 2);
        let s = !&s;
        assert_eq!(s, 1.into());
        let mut s = s;
        s.setbit(2);
        assert_eq!(s, 5.into());
    }

    #[test]
    fn check_export() {
        let s: Mpz = 0x100.into();
        let s = !&s;
        let mut buf = [0, 0, 0];
        export_obj(&s, &mut buf).expect("buffer should be large enough");
        assert_eq!(buf, [0xFF, 0xFE, 0xFF]);
        export_obj(&Mpz::zero(), &mut []).unwrap();
    }

    #[test]
    fn check_rem() {
        assert_eq!(mpz_crem_u16(&(-100i64).into(), 3), 1);
        assert_eq!(mpz_crem_u16(&(100i64).into(), 3), 2);
    }
}
