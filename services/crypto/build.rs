fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .include_file("proto.rs")
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/api/crypto/v1/crypto.proto",
                "../../proto/api/common/v1/types.proto",
                "../../proto/api/kms/v1/kms.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
