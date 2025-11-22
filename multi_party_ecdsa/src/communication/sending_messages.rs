use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SendingMessages {
    NormalMessage(usize, Vec<u8>),
    SubsetMessage(Vec<u8>),
    BroadcastMessage(Vec<u8>),
    EmptyMsg,
    KeyGenSuccessWithResult(Vec<String>),
    KeyRefreshSuccessWithResult(Vec<String>),
    SignSuccessWithResult(String),
}
