use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    let protos = &[
        "proto/hearth/identity/v1/identity.proto",
        "proto/hearth/identity/v1/oauth.proto",
        "proto/hearth/authz/v1/authz.proto",
        "proto/hearth/events/v1/audit.proto",
    ];

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    // Compile proto files with prost, generating file descriptor set for pbjson.
    let descriptor_path = out_dir.join("proto_descriptor.bin");
    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(protos, &[proto_dir])?;

    // Generate serde (JSON) implementations from the descriptor set.
    let descriptor_set = std::fs::read(&descriptor_path)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_set)?
        .preserve_proto_field_names()
        .build(&[
            ".hearth.identity.v1",
            ".hearth.authz.v1",
            ".hearth.events.v1",
        ])?;

    // Re-run build if any proto file changes.
    println!("cargo:rerun-if-changed=proto/");
    Ok(())
}
