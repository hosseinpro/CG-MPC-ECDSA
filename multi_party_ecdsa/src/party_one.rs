use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::signature::*;
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
}
