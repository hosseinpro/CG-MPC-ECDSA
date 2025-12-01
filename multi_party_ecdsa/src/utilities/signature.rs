use crate::utilities::error::MulEcdsaError;
use crate::utilities::class_group::scalar_to_bigint;
use k256::{Scalar, ProjectivePoint};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: Scalar,
    pub r: Scalar,
}

impl Signature {
    pub fn verify(&self, pubkey: &ProjectivePoint, message: &Scalar) -> Result<(), MulEcdsaError> {
        // secp256k1 order
        let q = BigInt::parse_bytes(b"115792089237316195423570985008687907852837564279074904382605163141518161494337", 10).unwrap();

        let s_inv = self.s.invert().unwrap_or(Scalar::ZERO);
        let u1 = ProjectivePoint::GENERATOR * (*message * s_inv);
        let u2 = *pubkey * (self.r * s_inv);

        // Get x-coordinate of u1 + u2
        let u1_plus_u2_point = u1 + u2;
        let affine = u1_plus_u2_point.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes = encoded.x().ok_or(MulEcdsaError::VrfyMultiECDSAFailed)?;
        let u1_plus_u2_x = BigInt::from_bytes_be(Sign::Plus, x_bytes);

        let r_bigint = scalar_to_bigint(&self.r);
        let s_bigint = scalar_to_bigint(&self.s);
        
        // second condition is against malleability
        if r_bigint == u1_plus_u2_x && s_bigint < &q - &s_bigint
        {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyMultiECDSAFailed)
        }
    }
}
