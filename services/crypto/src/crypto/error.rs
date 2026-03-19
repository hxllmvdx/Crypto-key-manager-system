use ring::error::Unspecified;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length")]
    InvalidKeyLengthError,

    #[error("Encryption failed")]
    EncryptionError,

    #[error("Decryption failed")]
    DecryptionError,

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithmError,

    #[error("Unspecified error")]
    UnspecifiedError,
}

impl From<Unspecified> for CryptoError {
    fn from(_: Unspecified) -> Self {
        CryptoError::UnspecifiedError
    }
}
