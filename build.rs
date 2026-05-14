use std::path::PathBuf;
use std::process::Command;

const GENERATED_DIR: &str = "src/protocol/generated";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    compile_tailwind_if_available();

    let proto_dir = PathBuf::from("proto");
    let protos = &[
        "proto/hearth/identity/v1/identity.proto",
        "proto/hearth/identity/v1/oauth.proto",
        "proto/hearth/rbac/v1/rbac.proto",
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
    let proto_dir_str = proto_dir.to_str().expect("proto dir is valid UTF-8");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&generated)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(protos, &[proto_dir_str])?;

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
            ".hearth.rbac.v1",
            ".hearth.events.v1",
        ])?;

    // Re-run build if any proto file changes.
    println!("cargo:rerun-if-changed=proto/");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}

/// Compiles `ui/input.css` → `src/protocol/web/assets/app.css` when the
/// Tailwind CLI shim is present. No-op on fresh clones without the CLI, so
/// `cargo build` still works for anyone who just wants the server binary —
/// the checked-in `app.css` is used as-is. Emits `rerun-if-changed` markers
/// so an edit to `input.css`, the Tailwind config, or any template triggers
/// a rebuild of the stylesheet on the next `cargo build`.
fn compile_tailwind_if_available() {
    // Always watch these paths — whether or not the CLI exists today, we want
    // the next build to pick up changes if the CLI is added later.
    println!("cargo:rerun-if-changed=ui/input.css");
    println!("cargo:rerun-if-changed=ui/tailwind.config.js");
    println!("cargo:rerun-if-changed=templates");

    let cli = PathBuf::from("ui/tailwindcss");
    if !cli.exists() {
        println!(
            "cargo:warning=ui/tailwindcss not found — skipping Tailwind build. \
             Using checked-in src/protocol/web/assets/app.css."
        );
        return;
    }

    let output = Command::new(&cli)
        .current_dir("ui")
        .args([
            "-i",
            "input.css",
            "-o",
            "../src/protocol/web/assets/app.css",
            "--minify",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("cargo:warning=Tailwind CSS rebuilt");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "cargo:warning=Tailwind build exited with {} — continuing with existing app.css. stderr: {}",
                out.status, stderr
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=failed to invoke ui/tailwindcss ({e}) — continuing with existing app.css"
            );
        }
    }
}
