use crate::utilities::dl_com_zk::*;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::k256_helpers::DLogProof;
use k256::{Scalar, ProjectivePoint};
use k256::elliptic_curve::Field;
use crate::utilities::class_group::scalar_from_bigint;
use num_bigint::BigInt;
use rand::rngs::OsRng;
use crate::shared::*;

#[derive(Clone, Debug)]
pub struct Sign {
    pub nonce_secret_share: Scalar,
    pub nonce_public_share: ProjectivePoint,
    pub dl_com_zk_com: DLComZK,
    pub key_store: Option<KeyStore>,
    pub reshared_secret_share: Scalar,
    pub r1_rec: Scalar,
    pub r_x: Scalar,
    pub msg_set: bool,
}

impl Sign {
    pub fn new() -> Result<Self, MulEcdsaError> {
        let nonce_secret_share = Scalar::random(&mut OsRng);
        let nonce_public_share = ProjectivePoint::GENERATOR * nonce_secret_share;
        let dl_com_zk_com = DLComZK::new(&nonce_secret_share, &nonce_public_share);
        
        let ret = Self {
            nonce_secret_share,
            nonce_public_share,
            dl_com_zk_com: dl_com_zk_com,
            key_store: None,
            reshared_secret_share: Scalar::random(&mut OsRng),
            r1_rec: Scalar::random(&mut OsRng),
            r_x: Scalar::random(&mut OsRng),
            msg_set: false,
        };
        Ok(ret)
    }

    pub fn generate_nonce_com(&self) -> DLCommitments {
        self.dl_com_zk_com.commitments.clone()
    }

    pub fn verify_generate_mta_consistency(
        &mut self,
        t_b: Scalar,
        mta_consis_rec: &MtaConsistencyMsg,
    ) -> Result<(), String> {
        if ProjectivePoint::GENERATOR * (t_b + mta_consis_rec.cc)
            != mta_consis_rec.reshared_public_share
                * (mta_consis_rec.r1 + self.nonce_secret_share)
                - mta_consis_rec.public_key
        {
            return Err("Verify Mta Consistency Failed".to_string());
        }
        let reshared_secret_share = self
            .key_store
            .as_ref()
            .unwrap()
            .secret_share
            - t_b
            - mta_consis_rec.cc;
        self.reshared_secret_share = reshared_secret_share;
        self.r1_rec = mta_consis_rec.r1;
        Ok(())
    }

    pub fn verify_send_nonce_ke_msg(
        &mut self,
        nonce_ke_rec: &NonceKEMsg,
    ) -> Result<CommWitness, String> {
        DLogProof::verify(&nonce_ke_rec.dl_proof, &nonce_ke_rec.nonce_public_key).map_err(|_| "Verify DLog failed".to_string())?;
        let r = nonce_ke_rec.nonce_public_key * (self.r1_rec + self.nonce_secret_share);
        
        // Get x-coordinate
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let affine = r.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes = encoded.x().ok_or("get x coor failed")?;
        let x_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, x_bytes);
        
        self.r_x = scalar_from_bigint(&x_bigint);
        Ok(self.dl_com_zk_com.witness.clone())
    }

    pub fn online_sign(&self, message_bytes: &[u8]) -> Scalar {
        // Process the message to sign - convert bytes to BigInt
        let message_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, message_bytes);
        let message = scalar_from_bigint(&message_bigint);

        let s_2 = (self.r1_rec + self.nonce_secret_share).invert().unwrap_or(Scalar::ZERO)
            * (message + self.r_x * self.reshared_secret_share);
        return s_2;
    }
}
