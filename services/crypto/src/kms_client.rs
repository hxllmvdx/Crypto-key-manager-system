use crate::error::ServiceError;
use crate::proto::kms::v1::{GetKeyRequest, Key, kms_service_client::KmsServiceClient};
use tonic::transport::Channel;

pub struct KMSClient {
    client: KmsServiceClient<Channel>,
}

impl KMSClient {
    pub async fn new(addr: String) -> Result<Self, ServiceError> {
        let client = KmsServiceClient::connect(addr).await?;
        Ok(Self { client })
    }

    pub async fn get_key(&mut self, key_id: &str) -> Result<Key, ServiceError> {
        let request = tonic::Request::new(GetKeyRequest {
            key_id: key_id.to_string(),
        });
        let response = self.client.get_key(request).await?;
        Ok(response.into_inner().key.unwrap())
    }
}
