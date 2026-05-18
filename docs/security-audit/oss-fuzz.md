# OSS-Fuzz Integration

Hearth is eligible for [OSS-Fuzz](https://github.com/google/oss-fuzz), Google's free
continuous fuzzing infrastructure for open source projects. OSS-Fuzz runs Hearth's fuzz
targets around the clock and automatically files GitHub issues for confirmed panics or
memory-safety violations.

## Current Fuzz Coverage

Hearth has 8 `cargo-fuzz` targets in `fuzz/fuzz_targets/`:

| Target | What it covers | Security relevance |
|---|---|---|
| `jwt_parse` | JWT header + payload parsing, signature verification | `alg:none` bypass, panics on malformed tokens |
| `saml_xml_parse` | All 5 SAML XML parsers (response, authn_request, logout, metadata) | XML parser differentials, namespace confusion, signature-wrapping |
| `webauthn_cbor_parse` | WebAuthn attestation object + COSE key parsing | Panic on malformed authenticator data |
| `federation_claims` | OIDC ID-token JSON claim parsing | Panic on deeply nested / adversarial JSON |
| `oidc_request_parse` | OIDC authorization request parameter parsing | Open-redirect, parameter injection |
| `credential_verify` | Argon2id / bcrypt / scrypt hash verification | Panic on malformed PHC strings |
| `wal_entry_deserialize` | WAL entry deserialization | Storage corruption recovery |
| `config_parse` | YAML configuration parsing | Panic on adversarial config input |

## Submitting to OSS-Fuzz

OSS-Fuzz integration is a pull request to [google/oss-fuzz](https://github.com/google/oss-fuzz).
The required files are:

### `projects/hearth/project.yaml`

```yaml
homepage: "https://github.com/anthropics/hearth"
language: rust
primary_contact: "therecluse26@protonmail.com"
auto_ccs:
  - "therecluse26@protonmail.com"
```

### `projects/hearth/build.sh`

```bash
#!/bin/bash -eu

cd "$SRC/hearth"

# Build all fuzz targets
cargo fuzz build --release

# Copy binaries to $OUT
for target in \
    jwt_parse \
    saml_xml_parse \
    webauthn_cbor_parse \
    federation_claims \
    oidc_request_parse \
    credential_verify \
    wal_entry_deserialize \
    config_parse; do
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/${target}" "$OUT/"
done
```

### `projects/hearth/Dockerfile`

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/anthropics/hearth $SRC/hearth
COPY build.sh $SRC/
WORKDIR $SRC/hearth
```

## Submitting the PR

1. Fork `google/oss-fuzz`
2. Create `projects/hearth/` with the three files above
3. Test locally: `python3 infra/helper.py build_image hearth && python3 infra/helper.py build_fuzzers hearth`
4. Open a PR to `google/oss-fuzz` — the OSS-Fuzz team reviews and merges within a few days

## Status

- [ ] PR submitted to google/oss-fuzz
- [ ] OSS-Fuzz project page live
- [ ] First fuzzing results received
