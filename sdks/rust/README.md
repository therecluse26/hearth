# Hearth Rust SDK

Rust client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

**SDK Specification:** [docs/sdk-spec.md](../../docs/sdk-spec.md)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hearth-sdk = "0.1"
```

## Quick start

```rust
use hearth_sdk::HearthClient;

let client = HearthClient::new("https://hearth.example.com", "<your-client-id>")?;
```

See the [SDK specification](../../docs/sdk-spec.md) for the full API contract, error taxonomy, middleware requirements, and security requirements.
