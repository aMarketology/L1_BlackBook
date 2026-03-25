fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile .proto files — generates Rust server + client stubs
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "proto/validator_relay.proto",
                "proto/settlement.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
