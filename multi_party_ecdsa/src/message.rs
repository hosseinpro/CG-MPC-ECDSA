use crate::party_one::{MtaConsistencyMsg, NonceKEMsg};
use crate::party_two::KeyGenSecRoungMsg;
use crate::utilities::cl_proof::*;
use crate::utilities::class_group::*;
use crate::utilities::dl_com_zk::*;
use k256::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum XAXPartyOneMsg {
    KeyGenPartyOneRoundOneMsg(DLCommitments),
    KeyGenPartyOneRoundTwoMsg(CommWitness),
    MtaPartyOneRoundOneMsg((CLProof, CLState)),
    SignPartyOneRoundOneMsg(MtaConsistencyMsg, NonceKEMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum XAXPartyTwoMsg {
    KeyGenFinish,
    KeyGenPartyTwoRoundOneMsg(KeyGenSecRoungMsg),
    SignPartyTwoRoundOneMsg(DLCommitments),
    MtaPartyTwoRoundOneMsg(Ciphertext),
    SignPartyTwoRoundTwoMsg(CommWitness, Scalar),
    SignPartyTwoRoundTwoMsgOnline(CommWitness),
    SignPartyTwoRoundThreeMsgOnline(Scalar),
}
