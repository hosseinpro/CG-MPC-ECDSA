use crate::utilities::cl_proof::*;
use crate::utilities::class_group::*;
use k256::Scalar;
use k256::elliptic_curve::Field;
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct PartyOne {
    pub b: Scalar,
    pub t_b: Scalar,
    pub cl_pub_key: PK,
    pub cl_priv_key: SK,
}

#[derive(Clone, Debug)]
pub struct PartyTwo {
    pub a: Scalar,
    pub t_a: Scalar,
}

impl PartyOne {
    pub fn new(b: Scalar) -> Self {
        let group = CLGroup::new();
        let (cl_priv_key, cl_pub_key) = group.keygen();
        Self {
            b,
            t_b: Scalar::random(&mut OsRng),
            cl_pub_key,
            cl_priv_key,
        }
    }

    pub fn generate_send_msg(&self, cl_pk: &PK) -> MTAFirstRoundMsg {
        let group = CLGroup::new();
        let (c_b, r) = CLGroup::encrypt(&group, cl_pk, &self.b);
        let witness = CLWit { x: self.b, r };
        let statement = CLState {
            cipher: c_b,
            cl_pub_key: (*cl_pk).clone(),
        };
        let cl_proof = CLProof::prove(&group, witness, statement.clone());
        MTAFirstRoundMsg {
            proof: cl_proof,
            state: statement,
        }
    }

    pub fn handle_receive_msg(&mut self, cl_sk: &SK, c_a: &Ciphertext) {
        let group = CLGroup::new();
        self.t_b = CLGroup::decrypt(&group, cl_sk, c_a);
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
        mta_msg: MTAFirstRoundMsg,
    ) -> Result<Ciphertext, String> {
        let group = CLGroup::new();
        let alpha_tag = Scalar::random(&mut OsRng);
        let alpha = -alpha_tag;
        self.t_a = alpha;

        //verify cl-encryption dl proof
        mta_msg.proof
            .verify(&group, mta_msg.state.clone())
            .map_err(|_| "verify cl encryption dl proof failed")?;
        let encrypted_alpha_tag = CLGroup::encrypt(&group, &mta_msg.state.cl_pub_key, &alpha_tag);
        let a_scal_c_b = CLGroup::eval_scal(&mta_msg.state.cipher, into_mpz(&self.a));
        let c_a = CLGroup::eval_sum(&a_scal_c_b, &encrypted_alpha_tag.0);
        return Ok(c_a);
    }
}
