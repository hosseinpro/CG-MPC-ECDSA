use crate::utilities::dl_com_zk::*;
use crate::utilities::signature::*;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::k256_helpers::DLogProof;
use k256::{Scalar, ProjectivePoint};
use k256::elliptic_curve::Field;
use crate::utilities::class_group::{scalar_to_bigint, scalar_from_bigint};
use num_bigint::BigInt;
use rand::rngs::OsRng;
use std::cmp;
use serde::{Deserialize, Serialize};
use crate::shared::KeyStore;

#[derive(Clone, Debug)]
pub struct Sign {
    pub dl_com_zk_com_rec: DLCommitments,
    pub reshared_secret_share: Scalar,
    pub reshared_public_share: ProjectivePoint,
    pub keygen_result: Option<KeyStore>,
    pub nonce_secret_share: Scalar,
    pub nonce_public_share: ProjectivePoint,
    pub r1: Scalar,
    pub r_x: Scalar,
    pub message: Scalar,
    pub dl_proof: DLogProof<ProjectivePoint>,
}

#[derive(Clone, Debug)]
pub struct MtaConsistencyMsg {
    pub reshared_public_share: ProjectivePoint,
    pub r1: Scalar,
    pub cc: Scalar,
}

impl Serialize for MtaConsistencyMsg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let mut state = serializer.serialize_struct("MtaConsistencyMsg", 3)?;
        // Serialize ProjectivePoint as compressed bytes (33 bytes)
        let point_bytes = self.reshared_public_share.to_affine().to_encoded_point(true);
        state.serialize_field("reshared_public_share", point_bytes.as_bytes())?;
        state.serialize_field("r1", &self.r1)?;
        state.serialize_field("cc", &self.cc)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MtaConsistencyMsg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        use k256::EncodedPoint;
        
        #[derive(Deserialize)]
        struct Helper {
            reshared_public_share: Vec<u8>,
            r1: Scalar,
            cc: Scalar,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        let encoded_point = EncodedPoint::from_bytes(&helper.reshared_public_share)
            .map_err(de::Error::custom)?;
        let affine = k256::AffinePoint::from_encoded_point(&encoded_point);
        let point = if affine.is_some().into() {
            ProjectivePoint::from(affine.unwrap())
        } else {
            return Err(de::Error::custom("invalid point encoding"));
        };
        
        Ok(MtaConsistencyMsg {
            reshared_public_share: point,
            r1: helper.r1,
            cc: helper.cc,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NonceKEMsg {
    pub nonce_public_key: ProjectivePoint,
    pub dl_proof: DLogProof<ProjectivePoint>,
}

impl Serialize for NonceKEMsg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let mut state = serializer.serialize_struct("NonceKEMsg", 2)?;
        // Serialize nonce_public_key as compressed bytes
        let nonce_bytes = self.nonce_public_key.to_affine().to_encoded_point(true);
        state.serialize_field("nonce_public_key", nonce_bytes.as_bytes())?;
        // Serialize pk_t_rand_commitment from dl_proof
        let commitment_bytes = self.dl_proof.pk_t_rand_commitment.to_affine().to_encoded_point(true);
        state.serialize_field("pk_t_rand_commitment", commitment_bytes.as_bytes())?;
        state.serialize_field("challenge_response", &self.dl_proof.challenge_response)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for NonceKEMsg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        use k256::EncodedPoint;
        use crate::utilities::k256_helpers::DLogProof;
        
        #[derive(Deserialize)]
        struct Helper {
            nonce_public_key: Vec<u8>,
            pk_t_rand_commitment: Vec<u8>,
            challenge_response: Scalar,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        
        // Deserialize nonce_public_key
        let nonce_encoded = EncodedPoint::from_bytes(&helper.nonce_public_key)
            .map_err(de::Error::custom)?;
        let nonce_affine = k256::AffinePoint::from_encoded_point(&nonce_encoded);
        let nonce_point = if nonce_affine.is_some().into() {
            ProjectivePoint::from(nonce_affine.unwrap())
        } else {
            return Err(de::Error::custom("invalid nonce point encoding"));
        };
        
        // Deserialize pk_t_rand_commitment
        let commitment_encoded = EncodedPoint::from_bytes(&helper.pk_t_rand_commitment)
            .map_err(de::Error::custom)?;
        let commitment_affine = k256::AffinePoint::from_encoded_point(&commitment_encoded);
        let commitment_point = if commitment_affine.is_some().into() {
            ProjectivePoint::from(commitment_affine.unwrap())
        } else {
            return Err(de::Error::custom("invalid commitment point encoding"));
        };
        
        Ok(NonceKEMsg {
            nonce_public_key: nonce_point,
            dl_proof: DLogProof {
                pk_t_rand_commitment: commitment_point,
                challenge_response: helper.challenge_response,
            },
        })
    }
}

impl Sign {
    pub fn new(message_bytes: &[u8]) -> Result<Self, MulEcdsaError> {
        let reshared_secret_share = Scalar::random(&mut OsRng);
        let reshared_public_share = ProjectivePoint::GENERATOR * reshared_secret_share;
        
        // Process the message to sign - convert bytes to BigInt
        let message_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, message_bytes);
        let message = scalar_from_bigint(&message_bigint);
        
        let nonce_secret_share = Scalar::random(&mut OsRng);
        let nonce_public_share = ProjectivePoint::GENERATOR * nonce_secret_share;
        let dl_proof = DLogProof::<ProjectivePoint>::prove(&nonce_secret_share);
        
        let ret = Self {
            dl_com_zk_com_rec: DLCommitments::default(),
            reshared_secret_share,
            reshared_public_share,
            keygen_result: None,
            nonce_secret_share,
            nonce_public_share,
            r1: Scalar::random(&mut OsRng),
            r_x: Scalar::random(&mut OsRng),
            message,
            dl_proof,
        };
        Ok(ret)
    }

    pub fn get_nonce_com(&mut self, dl_com_zk_com_rec: &DLCommitments) {
        self.dl_com_zk_com_rec = (*dl_com_zk_com_rec).clone();
    }

    pub fn generate_mta_consistency(&self, t_a: Scalar) -> MtaConsistencyMsg {
        let cc: Scalar = t_a
            + self.reshared_secret_share * self.r1
            - self
                .keygen_result
                .clone()
                .unwrap()
                .secret_share;
        MtaConsistencyMsg {
            reshared_public_share: self.reshared_public_share,
            r1: self.r1,
            cc,
        }
    }

    pub fn generate_nonce_ke_msg(&mut self) -> NonceKEMsg {
        NonceKEMsg {
            nonce_public_key: self.nonce_public_share,
            dl_proof: self.dl_proof.clone(),
        }
    }

    pub fn verify_nonce_ke_msg(&mut self, nonce_ke_rec: &CommWitness) -> Result<(), MulEcdsaError> {
        DLComZK::verify(&self.dl_com_zk_com_rec, nonce_ke_rec)?;
        DLogProof::verify(&nonce_ke_rec.d_log_proof, &nonce_ke_rec.public_share).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        
        let r = nonce_ke_rec.public_share * self.nonce_secret_share
            + ProjectivePoint::GENERATOR * (self.nonce_secret_share * self.r1);
        
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
        let s_tag = self.nonce_secret_share.invert().unwrap_or(Scalar::ZERO)
            * (*s2_rec + self.r_x * self.reshared_secret_share);
        
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
