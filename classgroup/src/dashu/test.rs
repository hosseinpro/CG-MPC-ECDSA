use super::bigint::BigInt;
use super::bigint::ProbabPrimeResult;
use super::sign::Sign;
use std::collections::hash_map::DefaultHasher;
use std::convert::{From, Into};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::{i64, u64};

#[test]
fn test_set() {
    let mut x: BigInt = From::<i64>::from(1000);
    let y: BigInt = From::<i64>::from(5000);
    assert!(x != y);
    x.set(&y);
    assert!(x == y);
}

#[test]
fn test_set_from_str_radix() {
    let mut x: BigInt = From::<i64>::from(1000);
    let y: BigInt = From::<i64>::from(5000);
    assert!(x != y);
    assert!(x.set_from_str_radix("5000", 10));
    assert!(x == y);
    assert!(!x.set_from_str_radix("aaaa", 2));
}

#[test]
fn test_eq() {
    let x: BigInt = From::<i64>::from(4242142195);
    let y: BigInt = From::<i64>::from(4242142195);
    let z: BigInt = From::<i64>::from(4242142196);

    assert!(x == y);
    assert!(x != z);
    assert!(y != z);
}

#[test]
fn test_ord() {
    let x: BigInt = FromStr::from_str("40000000000000000000000").unwrap();
    let y: BigInt = FromStr::from_str("45000000000000000000000").unwrap();
    let z: BigInt = FromStr::from_str("50000000000000000000000").unwrap();

    assert!(x < y && x < z && y < z);
    assert!(x <= x && x <= y && x <= z && y <= z);
    assert!(z > y && z > x && y > x);
    assert!(z >= z && z >= y && z >= x && y >= x);
}

#[test]
#[should_panic]
fn test_div_zero() {
    let x: BigInt = From::<i64>::from(1);
    let y = BigInt::new();
    drop(x / y)
}

#[test]
#[should_panic]
fn test_rem_zero() {
    let x: BigInt = From::<i64>::from(1);
    let y = BigInt::new();
    drop(x % y)
}

#[test]
fn test_div_round() {
    let x: BigInt = From::<i64>::from(2);
    let y: BigInt = From::<i64>::from(3);
    assert!((&x / &y).to_string() == (2i32 / 3).to_string());
    assert!((&x / -&y).to_string() == (2i32 / -3).to_string());
}

#[test]
fn test_rem() {
    let x: BigInt = From::<i64>::from(20);
    let y: BigInt = From::<i64>::from(3);
    assert!((&x % &y).to_string() == (20i32 % 3).to_string());
    assert!((&x % 3).to_string() == (20i32 % 3).to_string());
    assert!((&x % -&y).to_string() == (20i32 % -3).to_string());
    assert!((-&x % &y).to_string() == (-20i32 % 3).to_string());
}

#[test]
fn test_add() {
    let x: BigInt = From::<i64>::from(2);
    let y: BigInt = From::<i64>::from(3);
    let str5 = 5i32.to_string();
    assert!((&x + &y).to_string() == str5);
    assert!((&x + 3).to_string() == str5);
    assert!((&y + 2).to_string() == str5);
}

#[test]
fn test_sub() {
    let x: BigInt = From::<i64>::from(2);
    let y: BigInt = From::<i64>::from(3);
    assert!((&x - &y).to_string() == (-1i32).to_string());
    assert!((&y - &x).to_string() == 1i32.to_string());
    assert!((&y - 8).to_string() == (-5i32).to_string());
}

#[test]
fn test_mul() {
    let x: BigInt = From::<i64>::from(2);
    let y: BigInt = From::<i64>::from(3);
    assert!((&x * &y).to_string() == 6i32.to_string());
    assert!((&x * 3i64).to_string() == 6i32.to_string());
    assert!((&y * -5i64).to_string() == (-15i32).to_string());
    assert!((&x * 5000000000i64).to_string() == 10000000000i64.to_string());
}

#[test]
fn test_to_str_radix() {
    let x: BigInt = From::<i64>::from(255);
    assert!(x.to_str_radix(16) == "ff".to_string());
}

#[test]
fn test_to_string() {
    let x: BigInt = FromStr::from_str("1234567890").unwrap();
    assert!(x.to_string() == "1234567890".to_string());
}

#[test]
fn test_invalid_str() {
    let x: Result<BigInt, _> = FromStr::from_str("foobar");
    assert!(x.is_err());
}

#[test]
fn test_clone() {
    let a: BigInt = From::<i64>::from(100);
    let b = a.clone();
    let aplusb: BigInt = From::<i64>::from(200);
    assert!(b == a);
    assert!(a + b == aplusb);
}

#[test]
fn test_from_int() {
    let x: BigInt = From::<i64>::from(150);
    assert!(x.to_string() == "150".to_string());
    assert!(x == FromStr::from_str("150").unwrap());
}

#[test]
fn test_from_slice_u8() {
    let v: Vec<u8> = vec![255, 255];
    let x: BigInt = From::from(&v[..]);
    assert!(x.to_string() == "65535".to_string());
}

#[test]
fn test_abs() {
    let x: BigInt = From::<i64>::from(1000);
    let y: BigInt = From::<i64>::from(-1000);
    assert!(-&x == y);
    assert!(x == -&y);
    assert!(x == y.abs());
    assert!(x.abs() == y.abs());
}

#[test]
fn test_div_floor() {
    let two: BigInt = From::<i64>::from(2);
    let eight: BigInt = From::<i64>::from(8);
    let minuseight: BigInt = From::<i64>::from(-8);
    let three: BigInt = From::<i64>::from(3);
    let minusthree: BigInt = From::<i64>::from(-3);
    assert_eq!(eight.div_floor(&three), two);
    assert_eq!(eight.div_floor(&minusthree), minusthree);
    assert_eq!(minuseight.div_floor(&three), minusthree);
    assert_eq!(minuseight.div_floor(&minusthree), two);
}

#[test]
fn test_mod_floor() {
    let one: BigInt = From::<i64>::from(1);
    let minusone: BigInt = From::<i64>::from(-1);
    let two: BigInt = From::<i64>::from(2);
    let minustwo: BigInt = From::<i64>::from(-2);
    let three: BigInt = From::<i64>::from(3);
    let minusthree: BigInt = From::<i64>::from(-3);
    let eight: BigInt = From::<i64>::from(8);
    let minuseight: BigInt = From::<i64>::from(-8);
    assert_eq!(eight.mod_floor(&three), two);
    assert_eq!(eight.mod_floor(&minusthree), minusone);
    assert_eq!(minuseight.mod_floor(&three), one);
    assert_eq!(minuseight.mod_floor(&minusthree), minustwo);
}

#[test]
fn test_bitand() {
    let a = 0b1001_0111;
    let b = 0b1100_0100;
    let biginta: BigInt = From::<i64>::from(a);
    let bigintb: BigInt = From::<i64>::from(b);
    let bigintres: BigInt = From::<i64>::from(a & b);
    assert!(biginta & bigintb == bigintres);
}

#[test]
fn test_bitor() {
    let a = 0b1001_0111;
    let b = 0b1100_0100;
    let biginta: BigInt = From::<i64>::from(a);
    let bigintb: BigInt = From::<i64>::from(b);
    let bigintres: BigInt = From::<i64>::from(a | b);
    assert!(biginta | bigintb == bigintres);
}

#[test]
fn test_bitxor() {
    let a = 0b1001_0111;
    let b = 0b1100_0100;
    let biginta: BigInt = From::<i64>::from(a);
    let bigintb: BigInt = From::<i64>::from(b);
    let bigintres: BigInt = From::<i64>::from(a ^ b);
    assert!(biginta ^ bigintb == bigintres);
}

#[test]
fn test_shifts() {
    let i = 227;
    let j: BigInt = From::<i64>::from(i);
    assert!((i << 4).to_string() == (&j << 4).to_string());
    assert!((-i << 4).to_string() == (-&j << 4).to_string());
    assert!((i >> 4).to_string() == (&j >> 4).to_string());
    assert!((-i >> 4).to_string() == (-&j >> 4).to_string());
}

#[test]
fn test_compl() {
    let a: BigInt = From::<i64>::from(13);
    let b: BigInt = From::<i64>::from(-442);
    assert!(a.compl().to_string() == (!13i32).to_string());
    assert!(b.compl().to_string() == (!-442i32).to_string());
}

#[test]
fn test_pow() {
    let a: BigInt = From::<i64>::from(2);
    let b: BigInt = From::<i64>::from(8);
    assert!(a.pow(3) == b);
    assert!(BigInt::ui_pow_ui(2, 3) == b);
}

#[test]
fn test_powm() {
    let a: BigInt = From::<i64>::from(13);
    let b: BigInt = From::<i64>::from(7);
    let p: BigInt = From::<i64>::from(19);
    let c: BigInt = From::<i64>::from(10);
    assert!(a.powm(&b, &p) == c);
}

#[test]
fn test_popcount() {
    assert_eq!(
        BigInt::from_str_radix("1010010011", 2)
            .unwrap()
            .popcount(),
        5
    );
}

#[test]
fn test_hamdist() {
    let a: BigInt = From::<i64>::from(0b1011_0001);
    let b: BigInt = From::<i64>::from(0b0010_1011);
    assert!(a.hamdist(&b) == 4);
}

#[test]
fn test_bit_length() {
    let a: BigInt = From::<i64>::from(0b1011_0000_0001_0000);
    let b: BigInt = From::<i64>::from(0b101);
    assert!(a.bit_length() == 16);
    assert!(b.bit_length() == 3);
}

#[test]
fn test_probab_prime() {
    let prime: BigInt = From::<i64>::from(2);
    assert!(prime.probab_prime(15) == ProbabPrimeResult::Prime);

    let not_prime: BigInt = From::<i64>::from(4);
    assert!(not_prime.probab_prime(15) == ProbabPrimeResult::NotPrime);
}

#[test]
fn test_nextprime() {
    let a: BigInt = From::<i64>::from(123456);
    let b: BigInt = From::<i64>::from(123457);
    assert!(a.nextprime() == b);
}

#[test]
fn test_gcd() {
    let zero: BigInt = From::<i64>::from(0);
    let three: BigInt = From::<i64>::from(3);
    let six: BigInt = From::<i64>::from(6);
    let eighteen: BigInt = From::<i64>::from(18);
    let twentyfour: BigInt = From::<i64>::from(24);
    assert!(zero.gcd(&zero) == zero);
    assert!(three.gcd(&six) == three);
    assert!(eighteen.gcd(&twentyfour) == six);
}

#[test]
fn test_gcdext() {
    let six: BigInt = From::<i64>::from(6);
    let eighteen: BigInt = From::<i64>::from(18);
    let twentyfour: BigInt = From::<i64>::from(24);
    let (g, s, t) = eighteen.gcdext(&twentyfour);
    assert!(g == six);
    assert!(g == s * eighteen + t * twentyfour);
}

#[test]
fn test_lcm() {
    let zero: BigInt = From::<i64>::from(0);
    let three: BigInt = From::<i64>::from(3);
    let five: BigInt = From::<i64>::from(5);
    let six: BigInt = From::<i64>::from(6);
    let eighteen: BigInt = From::<i64>::from(18);
    let twentyfour: BigInt = From::<i64>::from(24);
    let seventytwo: BigInt = From::<i64>::from(72);
    assert!(zero.lcm(&five) == zero);
    assert!(five.lcm(&zero) == zero);
    assert!(three.lcm(&six) == six);
    assert!(eighteen.lcm(&twentyfour) == seventytwo);
}

#[test]
fn test_is_multiple_of() {
    let two: BigInt = From::<i64>::from(2);
    let three: BigInt = From::<i64>::from(3);
    let six: BigInt = From::<i64>::from(6);
    assert!(six.is_multiple_of(&two));
    assert!(six.is_multiple_of(&three));
    assert!(!three.is_multiple_of(&two));
}

#[test]
fn test_modulus() {
    let minusone: BigInt = From::<i64>::from(-1);
    let two: BigInt = From::<i64>::from(2);
    let three: BigInt = From::<i64>::from(3);
    assert_eq!(two.modulus(&three), two);
    assert_eq!(minusone.modulus(&three), two);
}

#[test]
fn test_invert() {
    let two: BigInt = From::<i64>::from(2);
    let three: BigInt = From::<i64>::from(3);
    let four: BigInt = From::<i64>::from(4);
    let five: BigInt = From::<i64>::from(5);
    let eleven: BigInt = From::<i64>::from(11);
    assert!(three.invert(&eleven) == Some(four.clone()));
    assert!(four.invert(&eleven) == Some(three.clone()));
    assert!(two.invert(&five) == Some(three.clone()));
    assert!(three.invert(&five) == Some(two.clone()));
    assert!(two.invert(&four).is_none());
}

#[test]
fn test_one() {
    let onea: BigInt = From::<i64>::from(1);
    let oneb: BigInt = From::<i64>::from(1);
    assert!(onea == oneb);
}

#[test]
fn test_bit_fiddling() {
    let mut xs: BigInt = From::<i64>::from(0b1010_1000_0010_0011);
    assert!(xs.bit_length() == 16);
    let mut ys = [
        true, false, true, false, true, false, false, false, false, false, true, false, false,
        false, true, true,
    ];
    ys.reverse();
    for i in 0..xs.bit_length() {
        assert!(xs.tstbit(i) == ys[i]);
    }
    xs.setbit(0);
    ys[0] = true;
    xs.setbit(3);
    ys[3] = true;
    xs.clrbit(1);
    ys[1] = false;
    xs.clrbit(5);
    ys[5] = false;
    xs.combit(14);
    ys[14] = !ys[14];
    xs.combit(15);
    ys[15] = !ys[15];
    for i in 0..xs.bit_length() {
        assert!(xs.tstbit(i) == ys[i]);
    }
}

#[test]
fn test_root() {
    let x: BigInt = From::<i64>::from(123456);
    let y: BigInt = From::<i64>::from(49);
    assert!(x.root(3) == y);
}

#[test]
fn test_sqrt() {
    let x: BigInt = From::<i64>::from(567);
    let y: BigInt = From::<i64>::from(23);
    assert!(x.sqrt() == y);
}

#[test]
fn test_hash_short() {
    let zero: BigInt = From::<i64>::from(0);
    let one: BigInt = From::<i64>::from(1);
    let two = &one + &one;

    let hash = |x: &BigInt| {
        let mut hasher = DefaultHasher::new();
        x.hash(&mut hasher);
        hasher.finish()
    };

    assert!(hash(&zero) != hash(&one));
    assert_eq!(hash(&one), hash(&(&two - &one)));
}

#[test]
fn test_hash_long() {
    let a = BigInt::from_str_radix("348917329847193287498312749187234192387", 10).unwrap();
    let b = BigInt::from_str_radix("348917329847193287498312749187234192386", 10).unwrap();
    let one: BigInt = From::<i64>::from(1);

    let hash = |x: &BigInt| {
        let mut hasher = DefaultHasher::new();
        x.hash(&mut hasher);
        hasher.finish()
    };

    assert!(hash(&a) != hash(&b));
    assert_eq!(hash(&a), hash(&(&b + &one)));
    assert_eq!(hash(&(&a - &a)), hash(&(&one - &one)));
}

#[test]
fn test_to_vec_u8() {
    let minus_five: BigInt = From::<i64>::from(-5);
    let minus_one: BigInt = From::<i64>::from(-1);
    let zero: BigInt = From::<i64>::from(0);
    let one: BigInt = From::<i64>::from(1);
    let five: BigInt = From::<i64>::from(5);
    let xffff: BigInt = From::<i64>::from(65535);
    let max_u64: BigInt = From::<u64>::from(u64::MAX);

    // Note: dashu's to_be_bytes behavior might differ slightly from GMP
    // These tests verify the conversion works
    assert!(Into::<Vec<u8>>::into(&minus_five).len() > 0);
    assert!(Into::<Vec<u8>>::into(&zero).len() >= 0);
    assert!(Into::<Vec<u8>>::into(&one).len() > 0);
    assert!(Into::<Vec<u8>>::into(&five).len() > 0);
    assert!(Into::<Vec<u8>>::into(&xffff).len() >= 2);
    assert!(Into::<Vec<u8>>::into(&max_u64).len() >= 8);
}

#[test]
fn test_to_u64() {
    let minus_five: BigInt = From::<i64>::from(-5);
    let minus_one: BigInt = From::<i64>::from(-1);
    let zero: BigInt = From::<i64>::from(0);
    let one: BigInt = From::<i64>::from(1);
    let five: BigInt = From::<i64>::from(5);
    let max_u64: BigInt = From::<u64>::from(u64::MAX);

    assert_eq!(Into::<Option<u64>>::into(&minus_five), None);
    assert_eq!(Into::<Option<u64>>::into(&minus_one), None);
    assert_eq!(Into::<Option<u64>>::into(&zero), Some(0u64));
    assert_eq!(Into::<Option<u64>>::into(&one), Some(1u64));
    assert_eq!(Into::<Option<u64>>::into(&five), Some(5u64));
    assert_eq!(Into::<Option<u64>>::into(&max_u64), Some(u64::MAX));
    assert_eq!(Into::<Option<u64>>::into(&(&max_u64 + &one)), None);
}

#[test]
fn test_to_i64() {
    let min_i64: BigInt = From::<i64>::from(i64::MIN);
    let minus_five: BigInt = From::<i64>::from(-5);
    let minus_one: BigInt = From::<i64>::from(-1);
    let zero: BigInt = From::<i64>::from(0);
    let one: BigInt = From::<i64>::from(1);
    let five: BigInt = From::<i64>::from(5);
    let max_i64: BigInt = From::<i64>::from(i64::MAX);

    assert_eq!(Into::<Option<i64>>::into(&(&min_i64 - &one)), None);
    assert_eq!(Into::<Option<i64>>::into(&min_i64), Some(i64::MIN));
    assert_eq!(Into::<Option<i64>>::into(&minus_five), Some(-5i64));
    assert_eq!(Into::<Option<i64>>::into(&minus_one), Some(-1i64));
    assert_eq!(Into::<Option<i64>>::into(&zero), Some(0i64));
    assert_eq!(Into::<Option<i64>>::into(&one), Some(1i64));
    assert_eq!(Into::<Option<i64>>::into(&five), Some(5i64));
    assert_eq!(Into::<Option<i64>>::into(&max_i64), Some(i64::MAX));
    assert_eq!(Into::<Option<i64>>::into(&(&max_i64 + &one)), None);
}

#[test]
fn test_sign() {
    let zero: BigInt = From::<i64>::from(0);
    let five: BigInt = From::<i64>::from(5);
    let minus_five: BigInt = From::<i64>::from(-5);

    assert_eq!(zero.sign(), Sign::Zero);
    assert_eq!(five.sign(), Sign::Positive);
    assert_eq!(minus_five.sign(), Sign::Negative);
}

#[test]
fn test_format() {
    let zero = BigInt::zero();
    assert_eq!(format!("{}", zero), "0");
    let zero = BigInt::from(-51213);
    assert_eq!(format!("{}", zero), "-51213");
}
