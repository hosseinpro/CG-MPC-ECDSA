use crate::protocols::message::{
    XAXPartyOneMsg, XAXPartyTwoMsg,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReceivingMessages {
    XAXTwoKeyGenMessagePartyOne(XAXPartyOneMsg),
    XAXTwoSignMessagePartyOne(XAXPartyOneMsg),
    XAXTwoKeyGenMessagePartyTwo(XAXPartyTwoMsg),
    XAXTwoSignMessagePartyTwo(XAXPartyTwoMsg),
    KeyGenBegin,
    SignBegin,
    KeyRefreshBegin,
    SetMessage(String),
    SignOnlineBegin,
    TwoPartySignRefresh(String, String), // SignRefresh(message, keygen_result_json)
    MultiPartySignRefresh(String, String, String, Vec<usize>), // SignRefresh(message, keygen_result_json, subset)
    // TBD: Extend it to errors
    NeedRefresh,
}
