use mockall::mock;
use mockall::predicate::*;
use rsa::pkcs1::EncodeRsaPrivateKey;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, async_trait};

use ::crypto::crypto;
use ::crypto::error::ServiceError;
use ::crypto::kms_client::KMSClientTrait;
use ::crypto::proto::common::v1::KeyType;
use ::crypto::proto::crypto::v1::{
    DecryptRequest, EncryptRequest, crypto_service_client::CryptoServiceClient,
    crypto_service_server::CryptoServiceServer,
};
use ::crypto::proto::kms::v1::{Key, KeyMetadata};
use ::crypto::server::CryptoServer;

mock! {
    pub KMSClient {}
    #[async_trait]
    impl KMSClientTrait for KMSClient {
        async fn get_key(&mut self, key_id: &str, user_id: &str) -> Result<Key, ServiceError>;
    }
}

fn create_test_server(mock_kms: MockKMSClient) -> CryptoServer {
    CryptoServer::new(Arc::new(Mutex::new(mock_kms)))
}

async fn run_test_server(
    server: CryptoServer,
) -> (
    CryptoServiceClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = CryptoServiceServer::new(server);

    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let channel = tonic::transport::Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = CryptoServiceClient::new(channel);
    (client, server_task)
}

fn generate_rsa_private_key() -> Vec<u8> {
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
    let private_key_der = private_key.to_pkcs1_der().expect("failed to serialize");
    private_key_der.as_bytes().to_vec()
}

#[tokio::test]
async fn test_encrypt_aes128_success() {
    let key_id = "key-aes128".to_string();
    let user_id = "".to_string();
    let key_material = vec![0x01; 16];
    let plaintext = b"Hello, AES-128!".to_vec();

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Aes128 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key.clone()));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = EncryptRequest {
        key_id,
        user_id,
        plaintext: plaintext.clone(),
    };
    let response = client.encrypt(Request::new(request)).await.unwrap();
    let encrypted = response.into_inner();

    assert!(!encrypted.ciphertext.is_empty());
    assert_eq!(encrypted.nonce_bytes.len(), 12);

    let decrypted =
        crypto::decrypt_aes128(&key_material, &encrypted.ciphertext, &encrypted.nonce_bytes)
            .unwrap();
    assert_eq!(decrypted, plaintext);

    server_task.abort();
}

#[tokio::test]
async fn test_encrypt_aes256_success() {
    let key_id = "key-aes256".to_string();
    let user_id = "".to_string();
    let key_material = vec![0x02; 32];
    let plaintext = b"Hello, AES-256!".to_vec();

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Aes256 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = EncryptRequest {
        key_id,
        user_id,
        plaintext: plaintext.clone(),
    };
    let response = client.encrypt(Request::new(request)).await.unwrap();
    let encrypted = response.into_inner();

    assert!(!encrypted.ciphertext.is_empty());
    assert_eq!(encrypted.nonce_bytes.len(), 12);

    let decrypted =
        crypto::decrypt_aes256(&key_material, &encrypted.ciphertext, &encrypted.nonce_bytes)
            .unwrap();
    assert_eq!(decrypted, plaintext);

    server_task.abort();
}

#[tokio::test]
async fn test_encrypt_rsa2048_success() {
    let key_id = "key-rsa".to_string();
    let user_id = "".to_string();
    let key_material = generate_rsa_private_key();
    let plaintext = b"RSA test".to_vec();

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Rsa2048 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key.clone()));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = EncryptRequest {
        key_id,
        user_id,
        plaintext: plaintext.clone(),
    };
    let response = client.encrypt(Request::new(request)).await.unwrap();
    let encrypted = response.into_inner();

    assert!(!encrypted.ciphertext.is_empty());
    assert!(encrypted.nonce_bytes.is_empty());

    let decrypted = crypto::decrypt_rsa2048(&key_material, &encrypted.ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    server_task.abort();
}

#[tokio::test]
async fn test_encrypt_key_not_found() {
    let key_id = "unknown".to_string();
    let user_id = "".to_string();
    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(|_, _| Err(ServiceError::KMSClientError("Key not found".to_string())));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = EncryptRequest {
        key_id,
        user_id,
        plaintext: b"data".to_vec(),
    };
    let result = client.encrypt(Request::new(request)).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);

    server_task.abort();
}

#[tokio::test]
async fn test_encrypt_unspecified_key_type() {
    let key_id = "bad-key".to_string();
    let user_id = "".to_string();
    let key = Key {
        key_material: vec![],
        metadata: Some(KeyMetadata {
            r#type: KeyType::Unspecified as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = EncryptRequest {
        key_id,
        user_id,
        plaintext: b"data".to_vec(),
    };
    let result = client.encrypt(Request::new(request)).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    server_task.abort();
}

#[tokio::test]
async fn test_decrypt_aes128_success() {
    let key_id = "key-aes128".to_string();
    let user_id = "".to_string();
    let key_material = vec![0x03; 16];
    let plaintext = b"Decrypt me!".to_vec();

    let (ciphertext, nonce) = crypto::encrypt_aes128(&key_material, &plaintext).unwrap();

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Aes128 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = DecryptRequest {
        key_id,
        user_id,
        ciphertext,
        nonce_bytes: nonce,
    };
    let response = client.decrypt(Request::new(request)).await.unwrap();
    let decrypted = response.into_inner();
    assert_eq!(decrypted.plaintext, plaintext);

    server_task.abort();
}

#[tokio::test]
async fn test_decrypt_aes256_success() {
    let key_id = "key-aes256".to_string();
    let user_id = "".to_string();
    let key_material = vec![0x04; 32];
    let plaintext = b"Another secret".to_vec();

    let (ciphertext, nonce) = crypto::encrypt_aes256(&key_material, &plaintext).unwrap();

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Aes256 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = DecryptRequest {
        key_id,
        user_id,
        ciphertext,
        nonce_bytes: nonce,
    };
    let response = client.decrypt(Request::new(request)).await.unwrap();
    let decrypted = response.into_inner();
    assert_eq!(decrypted.plaintext, plaintext);

    server_task.abort();
}

#[tokio::test]
async fn test_decrypt_rsa2048_success() {
    let key_id = "key-rsa".to_string();
    let user_id = "".to_string();
    let key_material = generate_rsa_private_key();
    let plaintext = b"RSA secret".to_vec();

    let ciphertext = crypto::encrypt_rsa2048(&key_material, &plaintext).unwrap();

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Rsa2048 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = DecryptRequest {
        key_id,
        user_id,
        ciphertext,
        nonce_bytes: vec![],
    };
    let response = client.decrypt(Request::new(request)).await.unwrap();
    let decrypted = response.into_inner();
    assert_eq!(decrypted.plaintext, plaintext);

    server_task.abort();
}

#[tokio::test]
async fn test_decrypt_key_not_found() {
    let key_id = "unknown".to_string();
    let user_id = "".to_string();
    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(|_, _| Err(ServiceError::KMSClientError("Key not found".to_string())));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = DecryptRequest {
        key_id,
        user_id,
        ciphertext: vec![1, 2, 3],
        nonce_bytes: vec![4, 5, 6],
    };
    let result = client.decrypt(Request::new(request)).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);

    server_task.abort();
}

#[tokio::test]
async fn test_decrypt_unspecified_key_type() {
    let key_id = "bad-key".to_string();
    let user_id = "".to_string();
    let key = Key {
        key_material: vec![],
        metadata: Some(KeyMetadata {
            r#type: KeyType::Unspecified as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = DecryptRequest {
        key_id,
        user_id,
        ciphertext: vec![1, 2, 3],
        nonce_bytes: vec![4, 5, 6],
    };
    let result = client.decrypt(Request::new(request)).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    server_task.abort();
}

#[tokio::test]
async fn test_decrypt_wrong_nonce() {
    let key_id = "key-aes128".to_string();
    let user_id = "".to_string();
    let key_material = vec![0x05; 16];
    let plaintext = b"Data".to_vec();

    let (ciphertext, _) = crypto::encrypt_aes128(&key_material, &plaintext).unwrap();
    let wrong_nonce = vec![0xff; 12];

    let key = Key {
        key_material: key_material.clone(),
        metadata: Some(KeyMetadata {
            r#type: KeyType::Aes128 as i32,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut mock = MockKMSClient::new();
    mock.expect_get_key()
        .with(eq(key_id.clone()), eq(user_id.clone()))
        .times(1)
        .return_once(move |_, _| Ok(key));

    let server = create_test_server(mock);
    let (mut client, server_task) = run_test_server(server).await;

    let request = DecryptRequest {
        key_id,
        user_id,
        ciphertext,
        nonce_bytes: wrong_nonce,
    };
    let result = client.decrypt(Request::new(request)).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);

    server_task.abort();
}
