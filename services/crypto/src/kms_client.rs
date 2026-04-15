use crate::error::ServiceError;
use crate::proto::kms::v1::{GetKeyRequest, Key, kms_service_client::KmsServiceClient};
use tonic::async_trait;
use tonic::transport::Channel;

#[async_trait]
pub trait KMSClientTrait: Send {
    async fn get_key(&mut self, key_id: &str, user_id: &str) -> Result<Key, ServiceError>;
}

pub struct KMSClient {
    client: KmsServiceClient<Channel>,
}

#[async_trait]
impl KMSClientTrait for KMSClient {
    async fn get_key(&mut self, key_id: &str, user_id: &str) -> Result<Key, ServiceError> {
        let request = tonic::Request::new(GetKeyRequest {
            key_id: key_id.to_string(),
            user_id: user_id.to_string(),
        });
        let response = self.client.get_key(request).await?;
        Ok(response.into_inner().key.unwrap())
    }
}

impl KMSClient {
    pub async fn new(addr: String) -> Result<Self, ServiceError> {
        let client = KmsServiceClient::connect(addr).await?;
        Ok(Self { client })
    }
}
