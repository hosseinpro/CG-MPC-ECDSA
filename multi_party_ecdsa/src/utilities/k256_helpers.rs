use k256::{ProjectivePoint, AffinePoint, Scalar};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{Field, PrimeField};
use num_bigint::{BigInt, Sign, RandBigInt};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;

pub trait ProjectivePointExt {
    fn bytes_compressed_to_big_int(&self) -> BigInt;
}

impl ProjectivePointExt for ProjectivePoint {
    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let encoded = self.to_affine().to_encoded_point(true);
        BigInt::from_bytes_be(Sign::Plus, encoded.as_bytes())
    }
}

impl ProjectivePointExt for AffinePoint {
    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let encoded = self.to_encoded_point(true);
        BigInt::from_bytes_be(Sign::Plus, encoded.as_bytes())
    }
}

// Simple DLogProof implementation (Schnorr proof)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLogProof<P> {
    pub pk_t_rand_commitment: P,
    pub challenge_response: Scalar,
}

impl DLogProof<AffinePoint> {
    pub fn prove(secret: &Scalar) -> Self {
        let generator = ProjectivePoint::GENERATOR;
        let random = Scalar::random(&mut OsRng);
        let pk_t_rand_commitment = (generator * random).to_affine();
        
        // Fiat-Shamir challenge
        let public_key = (generator * secret).to_affine();
        let challenge = Self::compute_challenge(&public_key, &pk_t_rand_commitment);
        
        // Response: r + challenge * secret
        let challenge_response = random + challenge * secret;
        
        Self {
            pk_t_rand_commitment,
            challenge_response,
        }
    }
    
    pub fn verify(&self, public_key: &ProjectivePoint) -> Result<(), String> {
        let generator = ProjectivePoint::GENERATOR;
        let challenge = Self::compute_challenge(&public_key.to_affine(), &self.pk_t_rand_commitment);
        
        // Verify: g^response == commitment * public_key^challenge
        let lhs = generator * self.challenge_response;
        let rhs = ProjectivePoint::from(self.pk_t_rand_commitment) + (*public_key * challenge);
        
        if lhs.to_affine() == rhs.to_affine() {
            Ok(())
        } else {
            Err("DLog proof verification failed".to_string())
        }
    }
    
    fn compute_challenge(public_key: &AffinePoint, commitment: &AffinePoint) -> Scalar {
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
