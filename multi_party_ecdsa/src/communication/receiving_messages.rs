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
}
