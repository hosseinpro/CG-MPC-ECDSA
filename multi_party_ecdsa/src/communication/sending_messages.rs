use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SendingMessages {
    BroadcastMessage(Vec<u8>),
    EmptyMsg,
    KeyGenSuccessWithResult(Vec<String>),
    SignSuccessWithResult(String),
}
