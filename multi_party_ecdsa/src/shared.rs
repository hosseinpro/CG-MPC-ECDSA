use k256::{Scalar, ProjectivePoint};
use serde::{Deserialize, Serialize};
use crate::utilities::k256_helpers::DLogProof;

#[derive(Clone, Debug)]
pub struct KeyStore {
    pub secret_share: Scalar,
    pub public_share: ProjectivePoint,
    pub public_signing_key: ProjectivePoint,
}

#[derive(Clone, Debug)]
pub struct MtaConsistencyMsg {
    pub reshared_public_share: ProjectivePoint,
    pub r1: Scalar,
    pub cc: Scalar,
    pub public_key: ProjectivePoint,
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
        let pk_bytes = self.public_key.to_affine().to_encoded_point(true);
        state.serialize_field("public_key", pk_bytes.as_bytes())?;
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
            public_key: Vec<u8>,
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
            public_key: {
                let pk_encoded = EncodedPoint::from_bytes(&helper.public_key)
                    .map_err(de::Error::custom)?;
                let pk_affine = k256::AffinePoint::from_encoded_point(&pk_encoded);
                if pk_affine.is_some().into() {
                    ProjectivePoint::from(pk_affine.unwrap())
                } else {
                    return Err(de::Error::custom("invalid public key point encoding"));
                }
            },
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
