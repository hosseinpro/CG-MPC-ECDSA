use crate::mta::PartyOne;
use crate::party_two::KeyGenSecRoungMsg;
use crate::message::*;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
//use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::signature::*;
//use crate::utilities::class_group::*;
use crate::communication::receiving_messages::ReceivingMessages;
use crate::communication::sending_messages::SendingMessages;
use crate::utilities::error::MulEcdsaError;
use k256::{Scalar, ProjectivePoint};
use k256::elliptic_curve::Field;
use crate::utilities::k256_helpers::{serialize_projective_point, deserialize_projective_point, DLogProof};
use crate::utilities::class_group::{scalar_to_bigint, scalar_from_bigint};
use num_bigint::BigInt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::cmp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGen {
    pub keypair: EcKeyPair,
    pub dl_com_zk_com: DLCommitments,
    pub dl_com_zk_wit: CommWitness,
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_share_rec: ProjectivePoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenResult {
    pub keypair: EcKeyPair,
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_signing_key: ProjectivePoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub dl_com_zk_com_rec: DLCommitments,
    pub reshared_keypair: EcKeyPair,
    pub keygen_result: Option<KeyGenResult>,
    pub nonce_pair: EcKeyPair,
    pub r1: Scalar,
    pub r_x: Scalar,
    pub message: Scalar,
    pub dl_proof: DLogProof<ProjectivePoint>,
    pub online_offline: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaConsistencyMsg {
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub reshared_public_share: ProjectivePoint,
    pub r1: Scalar,
    pub cc: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceKEMsg {
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub nonce_public_key: ProjectivePoint,
    pub dl_proof: DLogProof<ProjectivePoint>,
}

impl KeyGen {
    pub fn new() -> Self {
        let keypair = EcKeyPair::new();
        let dl_com_zk = DLComZK::new(&keypair);
        // Generate a random projective point
        let random_scalar = Scalar::random(&mut OsRng);
        let public_share_rec = ProjectivePoint::GENERATOR * random_scalar;
        Self {
            keypair,
            dl_com_zk_com: dl_com_zk.commitments,
            dl_com_zk_wit: dl_com_zk.witness,
            public_share_rec,
        }
    }

    pub fn generate_first_round_msg(&self) -> DLCommitments {
        self.dl_com_zk_com.clone()
    }

    pub fn get_msg_and_generate_third_roung_msg(
        &mut self,
        received_msg: &KeyGenSecRoungMsg,
    ) -> Result<CommWitness, MulEcdsaError> {
        DLogProof::verify(&received_msg.dl_proof, &received_msg.public_share).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        self.public_share_rec = received_msg.public_share;
        Ok(self.dl_com_zk_wit.clone())
    }

    pub fn generate_key_result(&self) -> KeyGenResult {
        KeyGenResult {
            keypair: self.keypair.clone(),
            public_signing_key: self.public_share_rec + self.keypair.public_share,
        }
    }

    pub fn process_begin_keygen(&mut self, index: usize) -> Result<SendingMessages, MulEcdsaError> {
        if index == 0 {
            let msg_send = ReceivingMessages::XAXTwoKeyGenMessagePartyOne(
                XAXPartyOneMsg::KeyGenPartyOneRoundOneMsg(self.generate_first_round_msg()),
            );
            let msg_bytes =
                bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
            return Ok(SendingMessages::BroadcastMessage(msg_bytes));
        } else {
            log::warn!("Please use index 0 party begin the sign...");
            return Ok(SendingMessages::EmptyMsg);
        }
    }

    pub fn msg_handler_keygen(
        &mut self,
        msg_received: &XAXPartyTwoMsg,
    ) -> Result<SendingMessages, MulEcdsaError> {
        match msg_received {
            XAXPartyTwoMsg::KeyGenPartyTwoRoundOneMsg(msg) => {
                log::info!("KeyGen: Receiving RoundOneMsg from index 1");
                let com_open = self.get_msg_and_generate_third_roung_msg(msg)?;
                let msg_send = ReceivingMessages::XAXTwoKeyGenMessagePartyOne(
                    XAXPartyOneMsg::KeyGenPartyOneRoundTwoMsg(com_open),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;

                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyTwoMsg::KeyGenFinish => {
                log::info!("KeyGen: Receiving KeyGenFinish from index 1");
                let keygen_result = self.generate_key_result();
                let keygen_json = serde_json::to_string(&keygen_result)
                    .map_err(|_| MulEcdsaError::ToStringFailed)?;
                return Ok(SendingMessages::KeyGenSuccessWithResult(vec![keygen_json]));
            }
            _ => return Ok(SendingMessages::EmptyMsg),
        }
    }
}

impl Sign {
    pub fn new(message_bytes: &[u8], online_offline: bool) -> Result<Self, MulEcdsaError> {
        let reshared_keypair: EcKeyPair = EcKeyPair::new();
        // Process the message to sign - convert bytes to BigInt
        let message_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, message_bytes);
        let message = scalar_from_bigint(&message_bigint);
        let nonce_pair = EcKeyPair::new();
        let dl_proof = DLogProof::<ProjectivePoint>::prove(&nonce_pair.secret_share);
        let ret = Self {
            dl_com_zk_com_rec: DLCommitments::default(),
            reshared_keypair,
            keygen_result: None,
            nonce_pair,
            r1: Scalar::random(&mut OsRng),
            r_x: Scalar::random(&mut OsRng),
            message,
            dl_proof,
            online_offline,
        };
        Ok(ret)
    }

    pub fn load_keygen_result(&mut self, keygen_json: &String) -> Result<(), MulEcdsaError> {
        // Load keygen result
        let keygen_result = KeyGenResult::from_json_string(keygen_json)?;
        self.keygen_result = Some(keygen_result);
        Ok(())
    }

    pub fn get_nonce_com(&mut self, dl_com_zk_com_rec: &DLCommitments) {
        self.dl_com_zk_com_rec = (*dl_com_zk_com_rec).clone();
    }

    pub fn generate_mta_consistency(&self, t_a: Scalar) -> MtaConsistencyMsg {
        let cc: Scalar = t_a
            + self.reshared_keypair.secret_share * self.r1
            - self
                .keygen_result
                .clone()
                .unwrap()
                .keypair
                .secret_share;
        MtaConsistencyMsg {
            reshared_public_share: self.reshared_keypair.public_share,
            r1: self.r1,
            cc,
        }
    }

    pub fn generate_nonce_ke_msg(&mut self) -> NonceKEMsg {
        NonceKEMsg {
            nonce_public_key: self.nonce_pair.public_share,
            dl_proof: self.dl_proof.clone(),
        }
    }

    pub fn verify_nonce_ke_msg(&mut self, nonce_ke_rec: &CommWitness) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, nonce_ke_rec)?;
        DLogProof::verify(&nonce_ke_rec.d_log_proof, &nonce_ke_rec.public_share).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        
        let r = nonce_ke_rec.public_share * self.nonce_pair.secret_share
            + ProjectivePoint::GENERATOR * (self.nonce_pair.secret_share * self.r1);
        
        // Get x-coordinate
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let affine = r.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes = encoded.x().ok_or(MulEcdsaError::XcoorNone)?;
        let x_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);
        
        self.r_x = scalar_from_bigint(&x_bigint);
        Ok(())
    }

    pub fn online_sign(&self, s2_rec: &Scalar) -> Result<Signature, MulEcdsaError> {
        let s_tag = self.nonce_pair.secret_share.invert().unwrap_or(Scalar::ZERO)
            * (*s2_rec + self.r_x * self.reshared_keypair.secret_share);
        
        // secp256k1 order
        let q = BigInt::parse_bytes(b"115792089237316195423570985008687907852837564279074904382605163141518161494337", 10).unwrap();
        let s_tag_bigint = scalar_to_bigint(&s_tag);
        let s = cmp::min(s_tag_bigint.clone(), &q - &s_tag_bigint);
        
        let signature = Signature {
            r: self.r_x,
            s: scalar_from_bigint(&s),
        };
        signature.verify(
            &self.keygen_result.clone().unwrap().public_signing_key,
            &self.message,
        )?;
        return Ok(signature);
    }

    pub fn msg_handler_sign(
        &mut self,
        msg_received: &XAXPartyTwoMsg,
        mta_party_one: &mut PartyOne,
    ) -> Result<SendingMessages, MulEcdsaError> {
        //let cl_keypair = ClKeyPair::new(&GROUP_128);
        match msg_received {
            XAXPartyTwoMsg::SignPartyTwoRoundOneMsg(msg) => {
                log::info!("Sign: Receiving RoundOneMsg from index 1");
                self.get_nonce_com(msg);
                let mta_first_round_msg =
                    mta_party_one.generate_send_msg(&mta_party_one.cl_keypair.cl_pub_key);
                let msg_send = ReceivingMessages::XAXTwoSignMessagePartyOne(
                    XAXPartyOneMsg::MtaPartyOneRoundOneMsg(mta_first_round_msg),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyTwoMsg::MtaPartyTwoRoundOneMsg(msg) => {
                mta_party_one
                    .handle_receive_msg(&mta_party_one.clone().cl_keypair.cl_priv_key, msg);
                let mta_consistency_msg = self.generate_mta_consistency(mta_party_one.t_b);
                let party_one_nonce_ke_msg = self.generate_nonce_ke_msg();
                let msg_send = ReceivingMessages::XAXTwoSignMessagePartyOne(
                    XAXPartyOneMsg::SignPartyOneRoundOneMsg(
                        mta_consistency_msg,
                        party_one_nonce_ke_msg,
                    ),
                );
                let msg_bytes =
                    bincode::serialize(&msg_send).map_err(|_| MulEcdsaError::SerializeFailed)?;
                return Ok(SendingMessages::BroadcastMessage(msg_bytes));
            }
            XAXPartyTwoMsg::SignPartyTwoRoundTwoMsg(noncekemsg, s_2) => {
                self.verify_nonce_ke_msg(noncekemsg).unwrap();
                let signature = self.online_sign(s_2).unwrap();
                println!("signature = {:?}", signature);
                let signature_json = serde_json::to_string(&signature)
                    .map_err(|_| MulEcdsaError::GenerateJsonStringFailed)?;
                return Ok(SendingMessages::SignSuccessWithResult(signature_json));
            }
            XAXPartyTwoMsg::SignPartyTwoRoundTwoMsgOnline(msg) => {
                self.verify_nonce_ke_msg(msg).unwrap();
                Ok(SendingMessages::EmptyMsg)
            }
            XAXPartyTwoMsg::SignPartyTwoRoundThreeMsgOnline(msg) => {
                let signature = self.online_sign(msg).unwrap();
                println!("signature = {:?}", signature);
                let signature_json = serde_json::to_string(&signature)
                    .map_err(|_| MulEcdsaError::GenerateJsonStringFailed)?;
                return Ok(SendingMessages::SignSuccessWithResult(signature_json));
            }
            _ => {
                log::warn!("Unsupported parse Received MessageType");
                return Ok(SendingMessages::EmptyMsg);
            }
        }
    }
}

impl KeyGenResult {
    pub fn from_json_string(json_string: &String) -> Result<Self, MulEcdsaError> {
        let ret = serde_json::from_str(json_string).map_err(|_| MulEcdsaError::FromStringFailed)?;
        Ok(ret)
    }
}
