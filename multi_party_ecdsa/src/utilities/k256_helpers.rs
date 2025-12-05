use k256::{ProjectivePoint, AffinePoint, Scalar};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{Field, PrimeField};
use classgroup::{Mpz, MpzSign};
use num_traits::{Zero, One};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;

// Serialization helpers for Scalar

pub trait ProjectivePointExt {
    fn bytes_compressed_to_big_int(&self) -> Mpz;
}

impl ProjectivePointExt for ProjectivePoint {
    fn bytes_compressed_to_big_int(&self) -> Mpz {
        let affine: AffinePoint = self.to_affine();
        let encoded = affine.to_encoded_point(true);
        Mpz::from_bytes_be(MpzSign::Plus, encoded.as_bytes())
    }
}

// Simple DLogProof implementation (Schnorr proof)
#[derive(Clone, Debug)]
pub struct DLogProof<P> {
    pub pk_t_rand_commitment: P,
    pub challenge_response: Scalar,
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
pub fn create_hash_commitment(message: &Mpz, blind_factor: &Mpz) -> Mpz {
    let mut hasher = Sha256::new();
    let (_, msg_bytes) = message.to_bytes_be();
    hasher.update(&msg_bytes);
    let (_, blind_bytes) = blind_factor.to_bytes_be();
    hasher.update(&blind_bytes);
    let hash = hasher.finalize();
    Mpz::from_bytes_be(MpzSign::Plus, &hash)
}

pub fn sample_bigint(bits: usize) -> Mpz {
    let mut rng = OsRng;
    let lower = Mpz::zero();
    let upper = Mpz::one() << bits;
    Mpz::gen_range(&mut rng, &lower, &upper)
}
