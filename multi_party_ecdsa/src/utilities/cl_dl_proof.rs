use crate::utilities::class_group::*;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_PARAMETER;
use crate::utilities::k256_helpers::ProjectivePointExt;
use classgroup::{Mpz, ClassGroup, MpzSign};
use classgroup::classgroup::*;
use k256::{Scalar, ProjectivePoint};
use num_traits::{Zero, One};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct CLDLState {
    pub cipher: Ciphertext,
    pub cl_pub_key: PK,
    pub dl_pub: ProjectivePoint,
}

#[derive(Clone, Debug)]
pub struct CLDLWit {
    pub dl_priv: Scalar,
    pub r: SK,
}

#[derive(Clone, Debug)]
pub struct CLDLProof {
    pub t1: GmpClassGroup,
    pub t2: GmpClassGroup,
    pub t3: ProjectivePoint,
    pub u1: Mpz,
    pub u2: Mpz,
}

impl CLDLProof {
    pub fn prove(group: &CLGroup, witness: CLDLWit, statement: CLDLState) -> Self {
        let upper = group.stilde.clone()
            * (Mpz::one() << 40)
            * (Mpz::one() << SECURITY_PARAMETER)
            * (Mpz::one() << 40);
        let r1 = sample_below(&upper);
        let r2_fe = Scalar::random(&mut OsRng);
        let r2 = into_mpz(&r2_fe);
        let fr2 = expo_f(&q(), &group.gq.discriminant(), &r2);
        let mut pkr1 = statement.cl_pub_key.0.clone();
        pkr1.pow(r1.clone());
        let t2 = fr2 * pkr1;
        let t3 = ProjectivePoint::GENERATOR * r2_fe;
        let mut t1 = group.gq.clone();
        t1.pow(r1.clone());
        let k = Self::challenge(
            &statement.cl_pub_key,
            t1.clone(),
            t2.clone(),
            t3,
            &statement.cipher,
            &statement.dl_pub,
        );
        let u1 = r1 + &k * &witness.r.0;
        let q_val = q();
        let u2 = mod_add(
            &r2,
            &(&k * &scalar_to_mpz(&witness.dl_priv)),
            &q_val,
        );

        Self {
            t1,
            t2,
            t3,
            u1,
            u2,
        }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    pub fn challenge(
        public_key: &PK,
        t1: GmpClassGroup,
        t2: GmpClassGroup,
        t3: ProjectivePoint,
        ciphertext: &Ciphertext,
        x_big: &ProjectivePoint,
    ) -> Mpz {
        let mut hasher = Sha256::new();
        let x_big_bytes = x_big.bytes_compressed_to_big_int();
        let (_, x_bytes) = x_big_bytes.to_bytes_be();
        hasher.update(&x_bytes);
        hasher.update(ciphertext.c1.to_bytes().as_ref());
        hasher.update(ciphertext.c2.to_bytes().as_ref());
        hasher.update(public_key.0.to_bytes().as_ref());
        hasher.update(t1.to_bytes().as_ref());
        hasher.update(t2.to_bytes().as_ref());
        let t3_bytes = t3.bytes_compressed_to_big_int();
        let (_, t3_be) = t3_bytes.to_bytes_be();
        hasher.update(&t3_be);
        let hash256 = hasher.finalize();

        let hash128 = &hash256[..SECURITY_PARAMETER / 8];
        Mpz::from_bytes_be(MpzSign::Plus, hash128)
    }

    pub fn verify(&self, group: &CLGroup, statement: CLDLState) -> Result<(), MulEcdsaError> {
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(
            &statement.cl_pub_key,
            self.t1.clone(),
            self.t2.clone(),
            self.t3,
            &statement.cipher,
            &statement.dl_pub,
        );

        let sample_size = group.stilde.clone()
            * (Mpz::one() << 40)
            * (Mpz::one() << SECURITY_PARAMETER)
            * ((Mpz::one() << 40) + Mpz::one());

        //length test u1:
        if &self.u1 > &sample_size || &self.u1 < &Mpz::zero() {
            flag = false;
        }
        // length test u2:
        let q_val = q();
        if &self.u2 > &q_val || &self.u2 < &Mpz::zero() {
            flag = false;
        }

        let mut c1k = statement.cipher.c1;
        c1k.pow(k.clone());
        let t1c1k = self.t1.clone() * c1k;
        let mut gqu1 = group.gq.clone();
        gqu1.pow(self.u1.clone());
        if t1c1k != gqu1 {
            flag = false;
        };

        // Verify EC part: g^u2 == t3 * pub^k
        let u2_scalar = scalar_from_mpz(&self.u2);
        let lhs = ProjectivePoint::GENERATOR * u2_scalar;
        let k_scalar = scalar_from_mpz(&k);
        let rhs = self.t3 + statement.dl_pub * k_scalar;
        if lhs != rhs {
            flag = false;
        }

        let mut pku1 = statement.cl_pub_key.0;
        pku1.pow(self.u1.clone());
        let fu2 = expo_f(&q_val, &group.gq.discriminant(), &self.u2);
        let mut c2k = statement.cipher.c2;
        c2k.pow(k);
        let t2c2k = self.t2.clone() * c2k;
        let pku1fu2 = pku1 * fu2;
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(MulEcdsaError::VrfyCLDLProofFailed),
        }
    }
}
