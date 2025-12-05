use std::fmt;
use std::error::Error;

/// Represents errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MulEcdsaError {
    OpenDLCommFailed,
    OpenCommZKFailed,
    VrfyDlogFailed,
    ZrExcceedSize,
    VrfyPromiseFailed,
    XcoorNone,
    VrfyMultiECDSAFailed,
    VrfyClassGroupFailed,
    GetIndexFailed,
    SerializeFailed,
    VrfyVSSFailed,
    ToStringFailed,
    FromStringFailed,
    PartyLessThanThreshold,
    LeftNotEqualRight,
    VrfySignPhaseOneMsgFailed,
    HandleSignPhaseTwoMsgFailed,
    OpenGeCommFailed,
    VrfyHomoElGamalFailed,
    VrfySumatFailed,
    ComputeDeltaSumFailed,
    VrfyElgamalProofFailed,
    VrfyClEncProofFailed,
    VrfyCLDLProofFailed,
    VrfyCLProofFailed,
    NotLoadKeyGenResult,
    InvalidPublicKey,
    FromHexFailed,
    GenerateJsonStringFailed,
    MissingMsg,
    InvertZero,
    GeneralError,
}

impl fmt::Display for MulEcdsaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MulEcdsaError::OpenDLCommFailed => write!(f, "Open dlcommitment failed"),
            MulEcdsaError::OpenCommZKFailed => write!(f, "Open zk-pok commitment failed"),
            MulEcdsaError::VrfyDlogFailed => write!(f, "Verify DLog failed"),
            MulEcdsaError::ZrExcceedSize => write!(f, "The size of zr excceeds sample size"),
            MulEcdsaError::VrfyPromiseFailed => write!(f, "Verify promise sigma protocol failed"),
            MulEcdsaError::XcoorNone => write!(f, "The return of x_coor() in None"),
            MulEcdsaError::VrfyMultiECDSAFailed => write!(f, "Verify multi-party ECDSA signature failed"),
            MulEcdsaError::VrfyClassGroupFailed => write!(f, "Verify class group pk failed"),
            MulEcdsaError::GetIndexFailed => write!(f, "Get index failed"),
            MulEcdsaError::SerializeFailed => write!(f, "Serialize failed"),
            MulEcdsaError::VrfyVSSFailed => write!(f, "Verify VSS failed"),
            MulEcdsaError::ToStringFailed => write!(f, "To string failed"),
            MulEcdsaError::FromStringFailed => write!(f, "From string failed"),
            MulEcdsaError::PartyLessThanThreshold => write!(f, "Party numbers less than the value of threshold in multiparty ecdsa keygen"),
            MulEcdsaError::LeftNotEqualRight => write!(f, "Left not equal to Right"),
            MulEcdsaError::VrfySignPhaseOneMsgFailed => write!(f, "Verify multiparty ecdsa sign phase one message failed"),
            MulEcdsaError::HandleSignPhaseTwoMsgFailed => write!(f, "Handle multiparty ecdsa sign phase two message failed"),
            MulEcdsaError::OpenGeCommFailed => write!(f, "Open general commitment failed"),
            MulEcdsaError::VrfyHomoElGamalFailed => write!(f, "Verify HomoElGamal failed"),
            MulEcdsaError::VrfySumatFailed => write!(f, "Verify sum_a_t failed"),
            MulEcdsaError::ComputeDeltaSumFailed => write!(f, "Compute delta sum msg in multiparty ecdsa sign phase two failed"),
            MulEcdsaError::VrfyElgamalProofFailed => write!(f, "Verify ElgamalProof failed"),
            MulEcdsaError::VrfyClEncProofFailed => write!(f, "Verify CLEncProof failed"),
            MulEcdsaError::VrfyCLDLProofFailed => write!(f, "Verify CLDLProof Failed"),
            MulEcdsaError::VrfyCLProofFailed => write!(f, "Verify CLProof Failed"),
            MulEcdsaError::NotLoadKeyGenResult => write!(f, "Not load keygen result"),
            MulEcdsaError::InvalidPublicKey => write!(f, "Invalid public key"),
            MulEcdsaError::FromHexFailed => write!(f, "From Hex Failed"),
            MulEcdsaError::GenerateJsonStringFailed => write!(f, "Generate Result Json String Failed"),
            MulEcdsaError::MissingMsg => write!(f, "Missing message to sign"),
            MulEcdsaError::InvertZero => write!(f, "Invert a zero element"),
            MulEcdsaError::GeneralError => write!(f, "General error"),
        }
    }
}

impl Error for MulEcdsaError {}
