use k256::{ProjectivePoint, AffinePoint, EncodedPoint, Scalar};
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use k256::elliptic_curve::{Field, PrimeField};
use num_bigint::{BigInt, Sign, RandBigInt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize, Deserializer, Serializer};
use serde::de::Error as DeError;
use rand::rngs::OsRng;

// Serialization helpers for Scalar
pub fn serialize_scalar<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = scalar.to_bytes();
    serializer.serialize_bytes(&bytes)
}

pub fn deserialize_scalar<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    if bytes.len() != 32 {
        return Err(DeError::custom("Invalid scalar length"));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    let ct_option = Scalar::from_repr(array.into());
    let scalar = if ct_option.is_some().into() {
        ct_option.unwrap()
    } else {
        return Err(DeError::custom("Invalid scalar"));
    };
    Ok(scalar)
}

// Serialization helpers for ProjectivePoint
pub fn serialize_projective_point<S>(point: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    serializer.serialize_bytes(encoded.as_bytes())
}

pub fn deserialize_projective_point<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let encoded = EncodedPoint::from_bytes(&bytes)
        .map_err(|e| DeError::custom(format!("Invalid encoded point: {:?}", e)))?;
    let affine_option = AffinePoint::from_encoded_point(&encoded);
    let affine = if affine_option.is_some().into() {
        affine_option.unwrap()
    } else {
        return Err(DeError::custom("Invalid point"));
    };
    Ok(ProjectivePoint::from(affine))
}


pub trait ProjectivePointExt {
    fn bytes_compressed_to_big_int(&self) -> BigInt;
}

impl ProjectivePointExt for ProjectivePoint {
    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let affine: AffinePoint = self.to_affine();
        let encoded = affine.to_encoded_point(true);
        BigInt::from_bytes_be(Sign::Plus, encoded.as_bytes())
    }
}

// Simple DLogProof implementation (Schnorr proof)
#[derive(Clone, Debug)]
pub struct DLogProof<P> {
    pub pk_t_rand_commitment: P,
    pub challenge_response: Scalar,
}

// Manual Serialize implementation for DLogProof<ProjectivePoint>
impl Serialize for DLogProof<ProjectivePoint> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DLogProof", 2)?;
        let affine = self.pk_t_rand_commitment.to_affine();
        let encoded = affine.to_encoded_point(true);
        let bytes = encoded.as_bytes().to_vec();
        state.serialize_field("pk_t_rand_commitment", &bytes)?;
        state.serialize_field("challenge_response", &self.challenge_response)?;
        state.end()
    }
}

// Manual Deserialize implementation for DLogProof<ProjectivePoint>
impl<'de> Deserialize<'de> for DLogProof<ProjectivePoint> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            PkTRandCommitment,
            ChallengeResponse,
        }

        struct DLogProofVisitor;

        impl<'de> Visitor<'de> for DLogProofVisitor {
            type Value = DLogProof<ProjectivePoint>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DLogProof")
            }

            fn visit_map<V>(self, mut map: V) -> Result<DLogProof<ProjectivePoint>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut pk_t_rand_commitment = None;
                let mut challenge_response = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PkTRandCommitment => {
                            if pk_t_rand_commitment.is_some() {
                                return Err(de::Error::duplicate_field("pk_t_rand_commitment"));
                            }
                            let bytes: Vec<u8> = map.next_value()?;
                            let encoded = EncodedPoint::from_bytes(&bytes)
                                .map_err(|e| de::Error::custom(format!("Invalid encoded point: {:?}", e)))?;
                            let affine_option = AffinePoint::from_encoded_point(&encoded);
                            let affine = if affine_option.is_some().into() {
                                affine_option.unwrap()
                            } else {
                                return Err(de::Error::custom("Invalid point"));
                            };
                            pk_t_rand_commitment = Some(ProjectivePoint::from(affine));
                        }
                        Field::ChallengeResponse => {
                            if challenge_response.is_some() {
                                return Err(de::Error::duplicate_field("challenge_response"));
                            }
                            challenge_response = Some(map.next_value()?);
                        }
                    }
                }
                let pk_t_rand_commitment = pk_t_rand_commitment
                    .ok_or_else(|| de::Error::missing_field("pk_t_rand_commitment"))?;
                let challenge_response = challenge_response
                    .ok_or_else(|| de::Error::missing_field("challenge_response"))?;
                Ok(DLogProof {
                    pk_t_rand_commitment,
                    challenge_response,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["pk_t_rand_commitment", "challenge_response"];
        deserializer.deserialize_struct("DLogProof", FIELDS, DLogProofVisitor)
    }
}

impl DLogProof<ProjectivePoint> {
    pub fn prove(secret: &Scalar) -> Self {
        let random = Scalar::random(&mut OsRng);
        let pk_t_rand_commitment = ProjectivePoint::GENERATOR * random;
        
        // Fiat-Shamir challenge
        let public_key = ProjectivePoint::GENERATOR * secret;
        let challenge = Self::compute_challenge(&public_key, &pk_t_rand_commitment);
        
        // Response: r + challenge * secret
        let challenge_response = random + challenge * secret;
        
        Self {
            pk_t_rand_commitment,
            challenge_response,
        }
    }
    
    pub fn verify(&self, public_key: &ProjectivePoint) -> Result<(), String> {
        let challenge = Self::compute_challenge(public_key, &self.pk_t_rand_commitment);
        
        // Verify: g^response == commitment * public_key^challenge
        let lhs = ProjectivePoint::GENERATOR * self.challenge_response;
        let rhs = self.pk_t_rand_commitment + (*public_key * challenge);
        
        if lhs == rhs {
            Ok(())
        } else {
            Err("DLog proof verification failed".to_string())
        }
    }
    
    fn compute_challenge(public_key: &ProjectivePoint, commitment: &ProjectivePoint) -> Scalar {
        let mut hasher = Sha256::new();
        let pk_bytes = public_key.bytes_compressed_to_big_int();
        let (_, pk_be) = pk_bytes.to_bytes_be();
        hasher.update(&pk_be);
        let comm_bytes = commitment.bytes_compressed_to_big_int();
        let (_, comm_be) = comm_bytes.to_bytes_be();
        hasher.update(&comm_be);
        let hash = hasher.finalize();
        
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..32]);
        Scalar::from_repr(scalar_bytes.into()).unwrap_or(Scalar::ZERO)
    }
}

// Hash commitment helper
pub fn create_hash_commitment(message: &BigInt, blind_factor: &BigInt) -> BigInt {
    let mut hasher = Sha256::new();
    let (_, msg_bytes) = message.to_bytes_be();
    hasher.update(&msg_bytes);
    let (_, blind_bytes) = blind_factor.to_bytes_be();
    hasher.update(&blind_bytes);
    let hash = hasher.finalize();
    BigInt::from_bytes_be(Sign::Plus, &hash)
}

pub fn sample_bigint(bits: usize) -> BigInt {
    let mut rng = OsRng;
    rng.gen_bigint(bits as u64)
}
