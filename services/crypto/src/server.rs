use crate::crypto;
use crate::error::ServiceError;
use crate::kms_client::KMSClient;
use crate::proto::common::v1::KeyType;
use crate::proto::crypto::v1::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, SignRequest, SignResponse,
    VerifyRequest, VerifyResponse, crypto_service_server::CryptoService,
};
use std::sync::Arc;
use tonic::{Request, Response, Status, async_trait};

pub struct CryptoServer {
    kms_client: Arc<tokio::sync::Mutex<KMSClient>>,
}

impl CryptoServer {
    pub fn new(kms_client: Arc<tokio::sync::Mutex<KMSClient>>) -> Self {
        Self { kms_client }
    }
}

#[async_trait]
impl CryptoService for CryptoServer {
    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let req = request.into_inner();

        let mut kms = self.kms_client.lock().await;

        let key = kms.get_key(&req.key_id).await?;

        match key.metadata.unwrap().r#type() {
            KeyType::Aes128 => {
                let (ciphertext, nonce_bytes) =
                    crypto::encrypt_aes128(&key.key_material, &req.plaintext)
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(EncryptResponse {
                    ciphertext: ciphertext,
                    nonce_bytes: nonce_bytes,
                }))
            }
            KeyType::Aes256 => {
                let (ciphertext, nonce_bytes) =
                    crypto::encrypt_aes256(&key.key_material, &req.plaintext)
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(EncryptResponse {
                    ciphertext: ciphertext,
                    nonce_bytes: nonce_bytes,
                }))
            }
            KeyType::Rsa2048 => {
                let ciphertext = crypto::encrypt_rsa2048(&key.key_material, &req.plaintext)
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(EncryptResponse {
                    ciphertext: ciphertext,
                    nonce_bytes: vec![],
                }))
            }
            KeyType::Unspecified => return Err(Status::from(ServiceError::UnknownKeyTypeError)),
        }
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let req = request.into_inner();

        let mut kms = self.kms_client.lock().await;

        let key = kms.get_key(&req.key_id).await?;

        match key.metadata.unwrap().r#type() {
            KeyType::Aes128 => {
                let plaintext =
                    crypto::decrypt_aes128(&key.key_material, &req.ciphertext, &req.nonce_bytes)
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(DecryptResponse {
                    plaintext: plaintext,
                }))
            }
            KeyType::Aes256 => {
                let plaintext =
                    crypto::decrypt_aes256(&key.key_material, &req.ciphertext, &req.nonce_bytes)
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(DecryptResponse {
                    plaintext: plaintext,
                }))
            }
            KeyType::Rsa2048 => {
                let plaintext = crypto::decrypt_rsa2048(&key.key_material, &req.ciphertext)
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(DecryptResponse {
                    plaintext: plaintext,
                }))
            }
            KeyType::Unspecified => return Err(Status::from(ServiceError::UnknownKeyTypeError)),
        }
    }

    async fn sign(&self, _request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("Sign method is not implemented"))
    }

    async fn verify(
        &self,
        _request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        Err(Status::unimplemented("Verify method is not implemented"))
    }
}
