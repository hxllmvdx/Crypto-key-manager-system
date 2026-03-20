use proto::crypto::v1::crypto_service_server::CryptoServiceServer;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub mod proto {
    tonic::include_proto!("proto");
}
pub mod config;
pub mod crypto;
pub mod error;
pub mod kms_client;
pub mod server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .init();

    let config = config::Config::from_env()?;

    let client = kms_client::KMSClient::new(config.kms_addr).await?;

    let server = server::CryptoServer::new(Arc::new(tokio::sync::Mutex::new(client)));

    let addr = format!("127.0.0.1:{}", config.service_port);
    info!("Starting crypto service on {}", addr);

    let server = tonic::transport::Server::builder()
        .add_service(CryptoServiceServer::new(server))
        .serve(addr.parse()?);

    if let Err(e) = server.await {
        error!("Crypto service error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
