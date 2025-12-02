use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_BITS;
use crate::utilities::k256_helpers::*;
use k256::{ProjectivePoint, Scalar};
use num_bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommitment {
    pub commitment: BigInt,
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommitmentOpen {
    pub blind_factor: BigInt,
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_share: ProjectivePoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLComZK {
    pub commitments: DLCommitments,
    pub witness: CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLCommitments {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    #[serde(serialize_with = "serialize_projective_point", deserialize_with = "deserialize_projective_point")]
    pub public_share: ProjectivePoint,
    pub d_log_proof: DLogProof<ProjectivePoint>,
}

impl DlogCommitment {
    pub fn new(public_share: &ProjectivePoint) -> Self {
        let blind_factor = sample_bigint(SECURITY_BITS);
        let commitment = create_hash_commitment(
            &public_share.bytes_compressed_to_big_int(),
            &blind_factor,
        );

        Self {
            commitment,
            open: DlogCommitmentOpen {
                blind_factor,
                public_share: public_share.clone(),
            },
        }
    }

    pub fn verify(&self) -> Result<(), MulEcdsaError> {
        if create_hash_commitment(
            &self.open.public_share.bytes_compressed_to_big_int(),
            &self.open.blind_factor,
        ) != self.commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        Ok(())
    }

    pub fn verify_dlog(
        commitment: &BigInt,
        open: &DlogCommitmentOpen,
    ) -> Result<(), MulEcdsaError> {
        if create_hash_commitment(
            &open.public_share.bytes_compressed_to_big_int(),
            &open.blind_factor,
        ) != *commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        Ok(())
    }

    pub fn get_public_share(&self) -> ProjectivePoint {
        self.open.public_share
    }
}

impl DLComZK {
    pub fn new(secret_share: &Scalar, public_share: &ProjectivePoint) -> Self {
        let d_log_proof = DLogProof::<ProjectivePoint>::prove(secret_share);
        // we use hash based commitment
        let pk_commitment_blind_factor = sample_bigint(SECURITY_BITS);
        let pk_commitment = create_hash_commitment(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = sample_bigint(SECURITY_BITS);
        let zk_pok_commitment = create_hash_commitment(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );

        let commitments = DLCommitments {
            pk_commitment,
            zk_pok_commitment,
        };

        let witness = CommWitness {
            pk_commitment_blind_factor,
            zk_pok_blind_factor,
            public_share: public_share.clone(),
            d_log_proof,
        };

        Self {
            commitments,
            witness,
        }
    }

    pub fn verify_commitments_and_dlog_proof(&self) -> Result<(), MulEcdsaError> {
        // Verify the commitment of DL
        if create_hash_commitment(
            &self.witness.public_share.bytes_compressed_to_big_int(),
            &self.witness.pk_commitment_blind_factor,
        ) != self.commitments.pk_commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        // Verify the commitment of proof
        if create_hash_commitment(
            &self
                .witness
                .d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &self.witness.zk_pok_blind_factor,
        ) != self.commitments.zk_pok_commitment
        {
            return Err(MulEcdsaError::OpenCommZKFailed);
        }

        // Verify DL proof
        self.witness.d_log_proof.verify(&self.witness.public_share).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(())
    }

    pub fn verify(commitment: &DLCommitments, witness: &CommWitness) -> Result<(), MulEcdsaError> {
        // Verify the commitment of DL
        if create_hash_commitment(
            &witness.public_share.bytes_compressed_to_big_int(),
            &witness.pk_commitment_blind_factor,
        ) != commitment.pk_commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        // Verify the commitment of proof
        if create_hash_commitment(
            &witness
                .d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &witness.zk_pok_blind_factor,
        ) != commitment.zk_pok_commitment
        {
            return Err(MulEcdsaError::OpenCommZKFailed);
        }

        // Verify DL proof
        witness.d_log_proof.verify(&witness.public_share).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(())
    }

    pub fn get_public_share(&self) -> ProjectivePoint {
        self.witness.public_share
    }
}

impl CommWitness {
    pub fn get_public_key(&self) -> &ProjectivePoint {
        &self.public_share
    }
}

impl Default for DLCommitments {
    fn default() -> DLCommitments {
        DLCommitments {
            pk_commitment: BigInt::zero(),
            zk_pok_commitment: BigInt::zero(),
        }
    }
}

#[test]
fn dl_com_zk_test() {
    use k256::elliptic_curve::Field;
    use rand::rngs::OsRng;
    
    let secret_share = Scalar::random(&mut OsRng);
    let public_share = ProjectivePoint::GENERATOR * secret_share;

    let dl_com_zk = DLComZK::new(&secret_share, &public_share);

    dl_com_zk.verify_commitments_and_dlog_proof().unwrap();
}
