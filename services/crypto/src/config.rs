use crate::error;
use serde::Deserialize;

fn default_kms_addr() -> String {
    "tcp://localhost:50051".to_string()
}

fn default_service_port() -> u16 {
    50052
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_kms_addr")]
    pub kms_addr: String,

    #[serde(default = "default_service_port")]
    pub service_port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self, error::ServiceError> {
        dotenvy::dotenv().ok();
        envy::from_env().map_err(|e| error::ServiceError::ConfigError(e))
    }
}
