// MTA (Multiplicative-to-Additive) protocol using pure Paillier encryption
use k256::Scalar;
use k256::elliptic_curve::Field;
use rand::rngs::OsRng;
use crate::utilities::paillier::{self, Pk, Sk, Ct, encrypt, decrypt, eval_sum, eval_scal, scalar_to_bigint};

#[derive(Clone, Debug)]
pub struct PartyOne {
    pub b: Scalar,
    pub t_b: Scalar,
    pub paillier_sk: Sk,
    pub paillier_pk: Pk,
}

#[derive(Clone, Debug)]
pub struct PartyTwo {
    pub a: Scalar,
    pub t_a: Scalar,
}

impl PartyOne {
    pub fn new(b: Scalar) -> Self {
        let (paillier_sk, paillier_pk) = paillier::keygen(2048);
        Self {
            b,
            t_b: Scalar::random(&mut OsRng),
            paillier_sk,
            paillier_pk,
        }
    }

    pub fn get_public_key(&self) -> &Pk {
        &self.paillier_pk
    }

    pub fn generate_send_msg(&self) -> Ct {
        encrypt(&self.paillier_pk, &self.b)
    }

    pub fn handle_receive_msg(&mut self, c_a: &Ct) {
        self.t_b = decrypt(&self.paillier_sk, c_a);
    }
}

impl PartyTwo {
    pub fn new(a: Scalar) -> Self {
        Self {
            a,
            t_a: Scalar::random(&mut OsRng),
        }
    }

    pub fn receive_and_send_msg(
        &mut self,
        c_b: Ct,
        pk: &Pk,
    ) -> Ct {
        let alpha_tag = Scalar::random(&mut OsRng);
        let alpha = -alpha_tag;
        self.t_a = alpha;

        // Compute a * c_b using scalar multiplication
        let a_bigint = scalar_to_bigint(&self.a);
        let a_scal_c_b = eval_scal(&c_b, &a_bigint, pk);
        
        // Encrypt alpha_tag and add to result
        let encrypted_alpha_tag = encrypt(pk, &alpha_tag);
        let c_a = eval_sum(&a_scal_c_b, &encrypted_alpha_tag, pk);
        
        c_a
    }
}
