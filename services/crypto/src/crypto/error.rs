use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Nonce validation error")]
    NonceValidationError,

    #[error("Invalid key length")]
    InvalidKeyLengthError,

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("PCKS1 to PrivateKey conversion failed: {0}")]
    Pkcs1ToPrivateKeyError(String),
}
