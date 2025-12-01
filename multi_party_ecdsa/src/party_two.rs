use crate::party_one::{MtaConsistencyMsg, NonceKEMsg};
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use k256::{Scalar, ProjectivePoint};
use k256::elliptic_curve::Field;
use crate::utilities::k256_helpers::{serialize_projective_point, deserialize_projective_point, DLogProof};
use crate::utilities::class_group::scalar_from_bigint;
use num_bigint::BigInt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGen {
    pub keypair: EcKeyPair,
    pub dl_com_zk_com_rec: DLCommitments,
    pub dl_com_zk_wit_rec: Option<CommWitness>,
    pub dlog_proof: DLogProof<ProjectivePoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenResult {
    pub keypair: EcKeyPair,
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_signing_key: ProjectivePoint,
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub other_public_key: ProjectivePoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenSecRoungMsg {
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_share: ProjectivePoint,
    pub dl_proof: DLogProof<ProjectivePoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub nonce_pair: EcKeyPair,
    pub dl_com_zk_com: DLComZK,
    pub keygen_result: Option<KeyGenResult>,
    pub message: Scalar,
    pub reshared_secret_share: Scalar,
    pub r1_rec: Scalar,
    pub r_x: Scalar,
    online_offline: bool,
    pub msg_set: bool,
}

impl KeyGen {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dlog_proof = DLogProof::<ProjectivePoint>::prove(&keypair.secret_share);
        Self {
            keypair,
            dl_com_zk_com_rec: DLCommitments::default(),
            dl_com_zk_wit_rec: None,
            dlog_proof,
        }
    }

    pub fn get_msg_and_generate_second_round_msg(
        &mut self,
        dl_com_zk_com_rec: &DLCommitments,
    ) -> KeyGenSecRoungMsg {
        self.dl_com_zk_com_rec = (*dl_com_zk_com_rec).clone();
        KeyGenSecRoungMsg {
            public_share: self.keypair.public_share,
            dl_proof: self.dlog_proof.clone(),
        }
    }

    pub fn verify_third_roung_msg(
        &mut self,
        dl_com_zk_wit: &CommWitness,
    ) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, dl_com_zk_wit)?;
        DLogProof::verify(&dl_com_zk_wit.d_log_proof, &dl_com_zk_wit.public_share).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        self.dl_com_zk_wit_rec = Some(dl_com_zk_wit.clone());
        Ok(())
    }

    pub fn generate_key_result(&self) -> KeyGenResult {
        KeyGenResult {
            keypair: self.keypair.clone(),
            public_signing_key: self.keypair.public_share
                + self.dl_com_zk_wit_rec.clone().unwrap().public_share,
            other_public_key: self.dl_com_zk_wit_rec.clone().unwrap().public_share,
        }
    }
}

impl Sign {
    pub fn new(message_bytes: &[u8], online_offline: bool) -> Result<Self, MulEcdsaError> {
        let nonce_pair = EcKeyPair::new();
        let dl_com_zk_com = DLComZK::new(&nonce_pair);
        // Process the message to sign - convert bytes to BigInt
        let message_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, message_bytes);
        let message = scalar_from_bigint(&message_bigint);
        let ret = Self {
            nonce_pair,
            dl_com_zk_com: dl_com_zk_com,
            keygen_result: None,
            message,
            reshared_secret_share: Scalar::random(&mut OsRng),
            r1_rec: Scalar::random(&mut OsRng),
            r_x: Scalar::random(&mut OsRng),
            online_offline,
            msg_set: false,
        };
        Ok(ret)
    }

    pub fn generate_nonce_com(&self) -> DLCommitments {
        self.dl_com_zk_com.commitments.clone()
    }

    pub fn verify_generate_mta_consistency(
        &mut self,
        t_b: Scalar,
        mta_consis_rec: &MtaConsistencyMsg,
    ) -> Result<(), String> {
        if ProjectivePoint::GENERATOR * (t_b + mta_consis_rec.cc)
            != mta_consis_rec.reshared_public_share
                * (mta_consis_rec.r1 + self.nonce_pair.secret_share)
                - self
                    .keygen_result
                    .as_ref()
                    .unwrap()
                    .other_public_key
        {
            return Err("Verify Mta Consistency Failed".to_string());
        }
        let reshared_secret_share = self
            .keygen_result
            .as_ref()
            .unwrap()
            .keypair
            .secret_share
            - t_b
            - mta_consis_rec.cc;
        self.reshared_secret_share = reshared_secret_share;
        self.r1_rec = mta_consis_rec.r1;
        Ok(())
    }

    pub fn verify_send_nonce_ke_msg(
        &mut self,
        nonce_ke_rec: &NonceKEMsg,
    ) -> Result<CommWitness, String> {
        DLogProof::verify(&nonce_ke_rec.dl_proof, &nonce_ke_rec.nonce_public_key).map_err(|_| "Verify DLog failed".to_string())?;
        let r = nonce_ke_rec.nonce_public_key * (self.r1_rec + self.nonce_pair.secret_share);
        
        // Get x-coordinate
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let affine = r.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes = encoded.x().ok_or("get x coor failed")?;
        let x_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);
        
        self.r_x = scalar_from_bigint(&x_bigint);
        Ok(self.dl_com_zk_com.witness.clone())
    }

    pub fn online_sign(&self) -> Scalar {
        let s_2 = (self.r1_rec + self.nonce_pair.secret_share).invert().unwrap_or(Scalar::ZERO)
            * (self.message + self.r_x * self.reshared_secret_share);
        return s_2;
    }

    pub fn set_msg(&mut self, message_bytes: &[u8]) -> Result<(), MulEcdsaError> {
        let message_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, message_bytes);
        let message: Scalar = scalar_from_bigint(&message_bigint);
        self.message = message;
        self.msg_set = true;
        Ok(())
    }

    pub fn load_keygen_result(&mut self, keygen_json: &String) -> Result<(), MulEcdsaError> {
        // Load keygen result
        let keygen_result = KeyGenResult::from_json_string(keygen_json)?;
        self.keygen_result = Some(keygen_result);
        Ok(())
    }
}

impl KeyGenResult {
    pub fn from_json_string(json_string: &String) -> Result<Self, MulEcdsaError> {
        let ret = serde_json::from_str(json_string).map_err(|_| MulEcdsaError::FromStringFailed)?;
        Ok(ret)
    }
}
