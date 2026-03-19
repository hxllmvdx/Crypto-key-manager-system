pub mod proto {
    tonic::include_proto!("proto");
}
pub mod config;
pub mod crypto;
pub mod error;
pub mod kms_client;

fn main() {
    println!("Hello, world!");
}
