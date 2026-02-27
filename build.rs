fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile all .proto files — generates Rust server + client stubs
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "proto/settlement.proto",
                "proto/validator_relay.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
