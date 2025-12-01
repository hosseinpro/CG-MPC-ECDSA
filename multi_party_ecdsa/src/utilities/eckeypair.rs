use k256::{Scalar, ProjectivePoint};
use k256::elliptic_curve::Field;
use crate::utilities::k256_helpers::{serialize_projective_point, deserialize_projective_point};
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_share: ProjectivePoint,
    pub secret_share: Scalar,
}

impl EcKeyPair {
    pub fn new() -> Self {
        let secret_share = Scalar::random(&mut OsRng);
        let public_share = ProjectivePoint::GENERATOR * secret_share;
        Self {
            secret_share,
            public_share,
        }
    }

    pub fn from_sk(sk: Scalar) -> Self {
        let public_share = ProjectivePoint::GENERATOR * sk;
        Self {
            secret_share: sk,
            public_share,
        }
    }

    pub fn get_public_key(&self) -> &ProjectivePoint {
        &self.public_share
    }

    pub fn get_secret_key(&self) -> &Scalar {
        &self.secret_share
    }
}
