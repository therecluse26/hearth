use std::path::PathBuf;

const GENERATED_DIR: &str = "src/protocol/generated";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    let protos = &[
        "proto/hearth/identity/v1/identity.proto",
        "proto/hearth/identity/v1/oauth.proto",
        "proto/hearth/authz/v1/authz.proto",
        "proto/hearth/events/v1/audit.proto",
    ];

    // Generated Rust lives under src/ so IDEs (RustRover, VS Code, Zed) can
    // statically index it. The files are gitignored; `cargo build` is the
    // source of truth for generation.
    let generated = PathBuf::from(GENERATED_DIR);
    std::fs::create_dir_all(&generated)?;

    // File descriptor set is consumed by both pbjson (for JSON codec) and
    // tonic-reflection (for runtime service discovery), so we write it into
    // the generated dir as a checked-in-but-gitignored artifact. It also
    // stays in OUT_DIR for pbjson-build.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("proto_descriptor.bin");
    let reflection_descriptor_path = generated.join("proto_descriptor.bin");

    // Compile proto files with tonic_build (wraps prost). Emits both message
    // types and service traits/clients. The file descriptor set is shared
    // with pbjson below.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&generated)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(protos, &[proto_dir])?;

    // Duplicate the descriptor set into the generated dir so tonic-reflection
    // can `include_bytes!` it at compile time without relying on OUT_DIR
    // layout leaking into source code.
    std::fs::copy(&descriptor_path, &reflection_descriptor_path)?;

    // Generate serde (JSON) implementations from the descriptor set.
    let descriptor_set = std::fs::read(&descriptor_path)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_set)?
        .preserve_proto_field_names()
        .out_dir(&generated)
        .build(&[
            ".hearth.identity.v1",
            ".hearth.authz.v1",
            ".hearth.events.v1",
        ])?;

    // Re-run build if any proto file changes.
    println!("cargo:rerun-if-changed=proto/");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
