use k256::{Scalar, ProjectivePoint};

#[derive(Clone, Debug)]
pub struct KeyStore {
    pub secret_share: Scalar,
    pub public_share: ProjectivePoint,
    pub public_signing_key: ProjectivePoint,
}