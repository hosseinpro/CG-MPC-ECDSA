use crate::utilities::cl_proof::*;
use crate::utilities::class_group::*;
use crate::utilities::clkeypair::*;
use k256::Scalar;
use k256::elliptic_curve::Field;
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct PartyOne {
    pub b: Scalar,
    pub t_b: Scalar,
    pub cl_keypair: ClKeyPair,
}

#[derive(Clone, Debug)]
pub struct PartyTwo {
    pub a: Scalar,
    pub t_a: Scalar,
}

impl PartyOne {
    pub fn new(b: Scalar) -> Self {
        let cl_keypair = ClKeyPair::new(&GROUP_128);
        Self {
            b,
            t_b: Scalar::random(&mut OsRng),
            cl_keypair,
        }
    }

    pub fn generate_send_msg(&self, cl_pk: &PK) -> (CLProof, CLState) {
        let (c_b, r) = CLGroup::encrypt(&GROUP_128, cl_pk, &self.b);
        let witness = CLWit { x: self.b, r };
        let statement = CLState {
            cipher: c_b,
            cl_pub_key: (*cl_pk).clone(),
        };
        let cl_proof = CLProof::prove(&GROUP_128, witness, statement.clone());
        (cl_proof, statement)
    }

    pub fn handle_receive_msg(&mut self, cl_sk: &SK, c_a: &Ciphertext) {
        self.t_b = CLGroup::decrypt(&GROUP_128, cl_sk, c_a);
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
        proof_cl: CLProof,
        statement: CLState,
    ) -> Result<Ciphertext, String> {
        let alpha_tag = Scalar::random(&mut OsRng);
        let alpha = -alpha_tag;
        self.t_a = alpha;

        //verify cl-encryption dl proof
        proof_cl
            .verify(&GROUP_128, statement.clone())
            .map_err(|_| "verify cl encryption dl proof failed")?;
        let encrypted_alpha_tag = CLGroup::encrypt(&GROUP_128, &statement.cl_pub_key, &alpha_tag);
        let a_scal_c_b = CLGroup::eval_scal(&statement.cipher, into_mpz(&self.a));
        let c_a = CLGroup::eval_sum(&a_scal_c_b, &encrypted_alpha_tag.0);
        return Ok(c_a);
    }
}
