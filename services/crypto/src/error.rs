use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("error with loading config from .env")]
    ConfigError(#[from] envy::Error),

    #[error("KMS client error: {0}")]
    KMSClientError(String),

    #[error("crypto operation failed")]
    CryptoError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Tonic transport error")]
    TonicTransportError(#[from] tonic::transport::Error),

    #[error("gRPC error: {0}")]
    GrpcError(#[from] tonic::Status),

    #[error("Unknown key type")]
    UnknownKeyTypeError,
}

impl From<ServiceError> for Status {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::ConfigError(source) => {
                Status::internal(format!("Configuration error: {}", source))
            }
            ServiceError::KMSClientError(msg) => {
                Status::unavailable(format!("KMS unavailable: {}", msg))
            }
            ServiceError::CryptoError(source) => {
                Status::invalid_argument(format!("Crypto error: {}", source))
            }
            ServiceError::TonicTransportError(source) => {
                Status::internal(format!("Tonic transport error: {}", source))
            }
            ServiceError::GrpcError(source) => source,
            ServiceError::UnknownKeyTypeError => Status::invalid_argument("Unknown key type"),
        }
    }
}
