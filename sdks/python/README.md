# Hearth Python SDK

Python client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/sdk-spec.md).

## Installation

```bash
pip install hearth-sdk
```

## Quick start

```python
from hearth import HearthClient

client = HearthClient(
    issuer_url="https://auth.example.com",
    client_id="my-client",
)
```

## Troubleshooting

**`DiscoveryError`** — verify `issuer_url` is reachable and returns a valid `/.well-known/openid-configuration`.

**`JWKSFetchError`** — check network connectivity to the JWKS endpoint. The SDK retries once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — JWT signature does not match any key in the JWKS. If the server recently rotated keys the SDK will re-fetch once automatically; persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured audience. Verify `client_id` matches the audience your authorization server issues.

See [docs/sdk-spec.md](../../docs/sdk-spec.md) Section 5 for the full error taxonomy.
