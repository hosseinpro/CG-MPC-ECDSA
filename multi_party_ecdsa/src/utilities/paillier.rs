use k256::Scalar;
use num_bigint::{BigInt, RandBigInt, Sign};
use num_traits::{Zero, One};
use rand::rngs::OsRng;

// Pure-Rust minimal Paillier implementation using num-bigint.

#[derive(Clone, Debug)]
pub struct Pk { pub n: BigInt, pub n2: BigInt }
#[derive(Clone, Debug)]
pub struct Sk { pub lam: BigInt, pub mu: BigInt, pub n: BigInt, pub n2: BigInt }

#[derive(Clone, Debug, PartialEq)]
pub struct Ct(pub BigInt);

pub fn q() -> BigInt {
    use num_traits::Num;
    BigInt::from_str_radix("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10).unwrap()
}

pub fn keygen(bits: usize) -> (Sk, Pk) {
    let mut rng = OsRng;
    let half = bits / 2;
    // ensure modulus n > q (secp256k1 order) so messages embed without wrap
    let n;
    let p;
    let qv;
    loop {
        let p_candidate = gen_prime(&mut rng, half);
        let q_candidate = gen_prime(&mut rng, half);
        let n_candidate = &p_candidate * &q_candidate;
        if n_candidate > q() {
            p = p_candidate;
            qv = q_candidate;
            n = n_candidate;
            break;
        }
    }
    let n2 = &n * &n;
    let p1 = &p - BigInt::one();
    let q1 = &qv - BigInt::one();
    let lam = lcm(&p1, &q1);
    // g = n+1
    // mu = (L(g^lambda mod n^2))^{-1} mod n, where L(u) = (u-1)/n
    let g = &n + BigInt::one();
    let u = mod_pow(&g, &lam, &n2);
    let l_val = (&u - BigInt::one()) / &n;
    let mu = mod_inv(&l_val, &n).expect("mu inverse exists");
    let pk = Pk { n: n.clone(), n2: n2.clone() };
    let sk = Sk { lam, mu, n, n2 };
    (sk, pk)
}

pub fn encrypt(pk: &Pk, m: &Scalar) -> Ct {
    let m_big = scalar_to_bigint(m);
    let m_mod = mod_floor(&m_big, &q());
    // choose r in Z_n^* (coprime with n)
    let r = sample_zn_star(&pk.n);
    let c = (BigInt::one() + &m_mod * &pk.n) % &pk.n2 * mod_pow(&r, &pk.n, &pk.n2) % &pk.n2;
    Ct(c)
}

pub fn decrypt(sk: &Sk, ct: &Ct) -> Scalar {
    let u = mod_pow(&ct.0, &sk.lam, &sk.n2);
    let l_val = (&u - BigInt::one()) / &sk.n;
    let m_big = (l_val * &sk.mu) % &sk.n;
    let m_mod = mod_floor(&m_big, &q());
    scalar_from_bigint(&m_mod)
}

pub fn eval_sum(a: &Ct, b: &Ct, pk: &Pk) -> Ct {
    Ct((&a.0 * &b.0) % &pk.n2)
}

pub fn eval_scal(ct: &Ct, k: &BigInt, pk: &Pk) -> Ct {
    Ct(mod_pow(&ct.0, k, &pk.n2))
}

pub fn sample_below(upper: &BigInt) -> BigInt {
    let mut rng = OsRng;
    rng.gen_bigint_range(&BigInt::zero(), upper)
}

fn sample_zn_star(n: &BigInt) -> BigInt {
    loop {
        let r = sample_below(n);
        if !r.is_zero() && gcd(r.clone(), n.clone()) == BigInt::one() {
            return r;
        }
    }
}

pub fn mod_floor(a: &BigInt, modulus: &BigInt) -> BigInt {
    ((a % modulus) + modulus) % modulus
}

pub fn scalar_to_bigint(s: &Scalar) -> BigInt {
    let bytes = s.to_bytes();
    BigInt::from_bytes_be(Sign::Plus, &bytes)
}

pub fn scalar_from_bigint(b: &BigInt) -> Scalar {
    let (_, bytes) = b.to_bytes_be();
    let mut arr = [0u8; 32];
    let len = core::cmp::min(bytes.len(), 32);
    if len > 0 {
        arr[32-len..].copy_from_slice(&bytes[bytes.len()-len..]);
    }
    use k256::elliptic_curve::PrimeField;
    Scalar::from_repr(arr.into()).unwrap_or(Scalar::ZERO)
}

fn gen_prime(rng: &mut OsRng, bits: usize) -> BigInt {
    loop {
        let mut p = rng.gen_bigint(bits as u64);
        // ensure odd and positive
        if p.sign() == Sign::Minus { p = -p; }
        p |= BigInt::one();
        // simple probabilistic primality (Miller-Rabin few rounds)
        if is_probably_prime(&p, 16) { return p; }
    }
}

fn is_probably_prime(n: &BigInt, k: u32) -> bool {
    if n <= &BigInt::from(3) { return *n == BigInt::from(2) || *n == BigInt::from(3); }
    if (n % 2u32).is_zero() { return false; }
    // write n-1 = d * 2^s
    let mut d = n - 1u32;
    let mut s = 0u32;
    while (&d % 2u32).is_zero() { d /= 2u32; s += 1; }
    let mut rng = OsRng;
    for _ in 0..k {
        let a = rng.gen_bigint_range(&BigInt::from(2), &(n - 2u32));
        let mut x = mod_pow(&a, &d, n);
        if x == BigInt::one() || x == n - 1u32 { continue; }
        let mut cont = false;
        for _ in 0..(s-1) {
            x = mod_pow(&x, &BigInt::from(2), n);
            if x == n - 1u32 { cont = true; break; }
        }
        if !cont { return false; }
    }
    true
}

fn mod_pow(base: &BigInt, exp: &BigInt, modu: &BigInt) -> BigInt {
    let mut result = BigInt::one();
    let mut b = mod_floor(base, modu);
    let mut e = exp.clone();
    while e > BigInt::zero() {
        if (&e & BigInt::one()) == BigInt::one() { result = (&result * &b) % modu; }
        b = (&b * &b) % modu;
        e >>= 1u32;
    }
    result
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() { (a.clone(), BigInt::one(), BigInt::zero()) }
    else {
        let (g, x, y) = egcd(b.clone(), a.clone() % b.clone());
        (g, y.clone(), x - (a / b) * y)
    }
}

fn mod_inv(a: &BigInt, modu: &BigInt) -> Option<BigInt> {
    let (g, x, _) = egcd(a.clone(), modu.clone());
    if g != BigInt::one() { None } else { Some(mod_floor(&x, modu)) }
}

fn lcm(a: &BigInt, b: &BigInt) -> BigInt {
    (a * b) / gcd(a.clone(), b.clone())
}

fn gcd(mut a: BigInt, mut b: BigInt) -> BigInt {
    while !b.is_zero() { let r = a % b.clone(); a = b; b = r; }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use k256::Scalar;
    use k256::elliptic_curve::Field;
    use num_bigint::BigInt;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sk, pk) = keygen(1024);
        let m = Scalar::random(&mut OsRng);
        let ct = encrypt(&pk, &m);
        let m2 = decrypt(&sk, &ct);
        assert_eq!(scalar_to_bigint(&m), scalar_to_bigint(&m2));
    }

    #[test]
    fn test_homomorphic_add_and_scalar() {
        let (sk, pk) = keygen(1024);
        let m1 = Scalar::random(&mut OsRng);
        let m2 = Scalar::random(&mut OsRng);
        let ct1 = encrypt(&pk, &m1);
        let ct2 = encrypt(&pk, &m2);

        // c_sum = Enc(m1) * Enc(m2) = Enc(m1 + m2)
        let c_sum = eval_sum(&ct1, &ct2, &pk);
        let sum_dec = decrypt(&sk, &c_sum);
    let expected_sum_big = scalar_to_bigint(&m1) + scalar_to_bigint(&m2);
    let expected_sum = scalar_from_bigint(&mod_floor(&expected_sum_big, &q()));
    assert_eq!(scalar_to_bigint(&sum_dec), scalar_to_bigint(&expected_sum));

        // c_scal = Enc(m1)^k = Enc(k*m1)
        let k = BigInt::from(7u32);
        let c_scal = eval_scal(&ct1, &k, &pk);
        let scal_dec = decrypt(&sk, &c_scal);
    let expected_scal_big = scalar_to_bigint(&m1) * k.clone();
    let expected_scal = scalar_from_bigint(&mod_floor(&expected_scal_big, &q()));
    assert_eq!(scalar_to_bigint(&scal_dec), scalar_to_bigint(&expected_scal));
    }
}

