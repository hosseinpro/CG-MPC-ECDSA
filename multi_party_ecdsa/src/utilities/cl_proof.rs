use crate::utilities::class_group::*;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_PARAMETER;
use classgroup::gmp::mpz::Mpz;
use classgroup::gmp_classgroup::*;
use classgroup::ClassGroup;
use k256::Scalar;
use k256::elliptic_curve::Field; 
use num_bigint::{BigInt, Sign};
use num_traits::{Zero, One};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct CLState {
    pub cipher: Ciphertext,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug)]
pub struct CLWit {
    pub x: Scalar,
    pub r: SK,
}

#[derive(Clone, Debug)]
pub struct CLProof {
    pub t1: GmpClassGroup,
    pub t2: GmpClassGroup,
    pub u1: Mpz,
    pub u2: Mpz,
}

impl CLProof {
    pub fn prove(group: &CLGroup, witness: CLWit, statement: CLState) -> Self {
        let upper = &mpz_to_bigint(group.stilde.clone())
            * BigInt::from(2i32).pow(40)
            * BigInt::from(2i32).pow(SECURITY_PARAMETER as u32)
            * BigInt::from(2i32).pow(40);
        let r1 = sample_below(&upper);
        let r1_mpz = bigint_to_mpz(r1);
        let r2_fe = Scalar::random(&mut OsRng);
        let r2 = into_mpz(&r2_fe);
        let fr2 = expo_f(&q(), &group.gq.discriminant(), &r2);
        let mut pkr1 = statement.cl_pub_key.0.clone();
        pkr1.pow(r1_mpz.clone());
        let t2 = fr2 * pkr1;
        let mut t1 = group.gq.clone();
        t1.pow(r1_mpz.clone());
        let k = Self::challenge(
            &statement.cl_pub_key,
            t1.clone(),
            t2.clone(),
            &statement.cipher,
        );
        let u1 = r1_mpz + &bigint_to_mpz(k.clone()) * &witness.r.0;
        let q_bigint = mpz_to_bigint(q());
        let u2 = mod_add(
            &mpz_to_bigint(r2),
            &(&k * scalar_to_bigint(&witness.x)),
            &q_bigint,
        );

        Self {
            t1,
            t2,
            u1,
            u2: bigint_to_mpz(u2),
        }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    pub fn challenge(
        public_key: &PK,
        t1: GmpClassGroup,
        t2: GmpClassGroup,
        ciphertext: &Ciphertext,
    ) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.update(<Vec<u8> as AsRef<[u8]>>::as_ref(&ciphertext.c1.to_bytes()));
        hasher.update(<Vec<u8> as AsRef<[u8]>>::as_ref(&ciphertext.c2.to_bytes()));
        hasher.update(<Vec<u8> as AsRef<[u8]>>::as_ref(&public_key.0.to_bytes()));
        hasher.update(<Vec<u8> as AsRef<[u8]>>::as_ref(&t1.to_bytes()));
        hasher.update(<Vec<u8> as AsRef<[u8]>>::as_ref(&t2.to_bytes()));
        let hash256 = hasher.finalize();

        let hash128 = &hash256[..SECURITY_PARAMETER / 8];
        BigInt::from_bytes_be(Sign::Plus, hash128)
    }

    pub fn verify(&self, group: &CLGroup, statement: CLState) -> Result<(), MulEcdsaError> {
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(
            &statement.cl_pub_key,
            self.t1.clone(),
            self.t2.clone(),
            &statement.cipher,
        );

        let sample_size = &mpz_to_bigint(group.stilde.clone())
            * BigInt::from(2i32).pow(40)
            * BigInt::from(2i32).pow(SECURITY_PARAMETER as u32)
            * (BigInt::from(2i32).pow(40) + BigInt::one());

        //length test u1:
        if &self.u1 > &bigint_to_mpz(sample_size) || &self.u1 < &Mpz::zero() {
            flag = false;
        }
        // length test u2:
        if &self.u2 > &q() || &self.u2 < &Mpz::zero() {
            flag = false;
        }

        let mut c1k = statement.cipher.c1;
        c1k.pow(bigint_to_mpz(k.clone()));
        let t1c1k = self.t1.clone() * c1k;
        let mut gqu1 = group.gq.clone();
        gqu1.pow(self.u1.clone());
        if t1c1k != gqu1 {
            flag = false;
        };

        let mut pku1 = statement.cl_pub_key.0;
        pku1.pow(self.u1.clone());
        let fu2 = expo_f(&q(), &group.gq.discriminant(), &self.u2);
        let mut c2k = statement.cipher.c2;
        c2k.pow(bigint_to_mpz(k));
        let t2c2k = self.t2.clone() * c2k;
        let pku1fu2 = pku1 * fu2;
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(MulEcdsaError::VrfyCLProofFailed),
        }
    }
}
