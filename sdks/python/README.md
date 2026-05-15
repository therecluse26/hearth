# Hearth Python SDK

Python client for the [Hearth](https://github.com/therecluse26/hearth) identity platform.

> **SDK Specification:** This SDK conforms to the [Hearth SDK Common Specification](../../docs/sdk-spec.md) (§1–§6, §8–§11).

## Installation

```bash
pip install hearth-sdk
# Flask middleware support:
pip install "hearth-sdk[flask]"
# FastAPI middleware support:
pip install "hearth-sdk[fastapi]"
```

## Quick start

```python
from hearth import HearthClient

client = HearthClient(
    issuer_url="https://auth.example.com",
    client_id="my-client",
    client_secret="my-secret",   # required for introspection
)

# Verify a JWT — signature + claims validated locally via JWKS.
token = client.verify_token(access_token)
print(token.subject)        # "user-abc"
print(token.scopes)         # ["openid", "profile"]
print(token.has_role("admin"))  # True / False

# Introspect a token (RFC 7662 — never cached).
result = client.introspect(access_token)
print(result.active)        # True / False
```

## Framework middleware

### Flask

```python
from flask import Flask, g
from hearth import HearthClient
from hearth.middleware import hearth_flask

app = Flask(__name__)
hearth = HearthClient(issuer_url="https://auth.example.com", client_id="my-app")

@app.route("/api/data")
@hearth_flask(hearth, required_scope="read:data")
def get_data():
    token = g.hearth_token   # VerifiedToken
    return {"user": token.subject}
```

### FastAPI

```python
from fastapi import FastAPI, Depends
from hearth import HearthClient, VerifiedToken
from hearth.middleware import hearth_fastapi

app = FastAPI()
hearth = HearthClient(issuer_url="https://auth.example.com", client_id="my-app")
auth = hearth_fastapi(hearth, required_scope="read:data")

@app.get("/api/data")
async def get_data(token: VerifiedToken = Depends(auth)):
    return {"user": token.subject}
```

## VerifiedToken API

| Property / Method | Returns | Description |
|---|---|---|
| `.subject` | `str` | `sub` claim |
| `.issuer` | `str` | `iss` claim |
| `.audience` | `list[str]` | `aud` claim (always a list) |
| `.issued_at` | `datetime \| None` | `iat` as UTC datetime |
| `.expires_at` | `datetime \| None` | `exp` as UTC datetime |
| `.not_before` | `datetime \| None` | `nbf` as UTC datetime |
| `.scope` | `str` | space-delimited scope string |
| `.scopes` | `list[str]` | parsed scope list |
| `.raw` | `dict` | copy of the full payload |
| `.get(key)` | `Any` | arbitrary claim by key |
| `.has_scope(s)` | `bool` | timing-safe scope check |
| `.has_role(r)` | `bool` | timing-safe Hearth `roles` check |
| `.has_permission(p)` | `bool` | timing-safe Hearth `permissions` check |

## Server compatibility matrix

| hearth-sdk version | Hearth server version |
|---|---|
| 0.2.x | ≥ 0.1.0 |

OIDC endpoints are auto-discovered via `/.well-known/openid-configuration`, so the
SDK is forward-compatible with any Hearth server that implements that standard endpoint.

## Troubleshooting

**`ConfigurationError`** — `issuer_url` is empty or not a valid URL.  Verify the
value passed to `HearthClient(issuer_url=...)`.

**`DiscoveryError`** — the `/.well-known/openid-configuration` endpoint is
unreachable or returned invalid JSON.  Check network connectivity and that
`issuer_url` points to a running Hearth instance.

**`JwksFetchError`** — the JWKS endpoint is down or returned a non-JSON body.
The SDK retries once on a cache miss before surfacing this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past.  Refresh the
token or re-authenticate.  Default clock-skew tolerance is 60 s.

**`TokenVerificationError`** — JWT signature does not match any key in the JWKS.
If the server recently rotated keys, the SDK re-fetches automatically; persistent
failures indicate a key mismatch or unsupported algorithm.

**`TokenClaimsError`** (and sub-types `TokenIssuerError`, `TokenAudienceError`,
`TokenNotYetValidError`) — a required claim failed validation.  Verify that
`issuer_url` and `client_id` match the values your authorization server issues.

**`IntrospectionError`** — the introspection endpoint is unreachable or returned
an error.  Ensure `client_secret` is set and the `introspection_endpoint` is
reachable from your server.

See [docs/sdk-spec.md](../../docs/sdk-spec.md) Section 5 for the full error taxonomy.
