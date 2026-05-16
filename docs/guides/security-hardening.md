# Security Hardening Guide

This guide documents security configuration recommendations for Hearth deployments. It is
aimed at production operators and complements the default configuration documented in
[CONFIGURATION.md](../specs/CONFIGURATION.md).

## Session TTL

### Default and recommended values

The `session_ttl` option controls how long a session remains valid after issuance or last
refresh. The built-in default is `24h`.

| Deployment context | Recommended `session_ttl` |
|---|---|
| High-security / admin consoles | `1h`–`4h` |
| Standard enterprise SaaS | `8h`–`24h` |
| Consumer applications | `7d`–`30d` |
| **Maximum recommended** | **`30d`** |

**Do not set `session_ttl` above 30 days.** Long-lived sessions increase the window of
exposure for stolen session tokens and make revocation less effective as a security control.
There is no hard upper limit enforced by Hearth — operators are responsible for choosing a
value appropriate for their threat model.

```yaml
auth:
  session_ttl: "8h"       # reasonable default for enterprise SaaS

realms:
  - name: internal-tools
    session_ttl: "4h"     # tighter for admin interfaces
  - name: customer-portal
    session_ttl: "30d"    # maximum recommended for consumer contexts
```

### Access and refresh token TTLs

Refresh tokens can extend session validity beyond the access token TTL. Ensure
`refresh_token_ttl` is set intentionally and is not longer than your `session_ttl`.

```yaml
auth:
  access_token_ttl: "15m"    # short-lived, minimises exposure window
  refresh_token_ttl: "8h"    # drives actual session length
  session_ttl: "8h"
```

---

## SAML 2.0

### Algorithm suite

Hearth's SAML implementation locks the algorithm suite to **Exclusive C14N 1.0 +
SHA-256 digests + RSA-SHA256 signatures**. SHA-1 digests and RSA-SHA1 signatures are
rejected unconditionally — algorithm downgrade is a common SAML attack vector.

### Attestation limitations

Hearth's WebAuthn implementation does not validate TPM or FIDO MDS attestation chains.
Only `none` and `packed` self-attestation are supported. This is a deliberate design choice:
- TPM/x5c attestation requires a live X.509 chain validation against the FIDO Metadata Service
  (MDS), which adds significant complexity and an external runtime dependency.
- `packed` self-attestation is the correct choice for most deployments; it verifies the
  authenticator's signature without requiring knowledge of the authenticator's make and model.

**Impact:** Hearth cannot enforce "only hardware authenticators from certified vendors"
policies. If your threat model requires attestation-level authenticator verification
(e.g., FIPS 140-3 Level 2 hardware requirement), Hearth's current WebAuthn implementation
is not a fit.

### SAML ACS URL validation

Hearth validates that the `AssertionConsumerServiceURL` in incoming `AuthnRequest` messages
matches a pre-registered ACS URL. Do not configure wildcard ACS URLs; always register the
exact endpoint URL.

---

## Secrets Management

### Host key

The host key (`HEARTH_MASTER_KEY`) encrypts all realm Key Encryption Keys (KEKs) at rest. It
is the most sensitive secret in a Hearth deployment.

- **Never commit the host key to version control.**
- Store it in a secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).
- Inject it at runtime via the `HEARTH_MASTER_KEY` environment variable.
- Rotate it by re-wrapping all realm KEKs (Hearth supports O(n files) rotation — only DEK
  headers are re-wrapped, not bulk data).

### OAuth client secrets

OAuth client secrets are stored as Argon2id hashes, not plaintext. Treat them like passwords:
- Generate at least 32 bytes of cryptographically random material.
- Rotate them immediately if compromised (Hearth supports multiple active secrets per client
  for zero-downtime rotation).

### SCIM bearer tokens

SCIM bearer tokens are SHA-256 hashed before storage and compared in constant time. Generate
them with at least 32 bytes of cryptographic randomness.

### Webhook signing secrets

Webhook signing secrets are HMAC-SHA256 keys. Generate at least 32 bytes of randomness.
Verify the `X-Hearth-Signature-256` header on all incoming webhook deliveries.

---

## TLS Configuration

Hearth uses `rustls` 0.23 and supports TLS 1.2 and TLS 1.3. TLS 1.0 and 1.1 are not
supported.

- **Terminate TLS at Hearth, not a reverse proxy**, unless you have a specific reason to use
  a proxy. Terminating at the proxy creates a plaintext hop between proxy and Hearth.
- Use the `tls` configuration block to point Hearth at your certificate and key files.
- Hearth supports hot-reload of TLS certificates without dropping existing connections.

---

## Dependency Vulnerability Scanning

Hearth ships with `deny.toml` which enforces `cargo deny` checks in CI. All CVE exceptions are
documented with justification. Known exceptions:

| Advisory | Crate | Justification |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa` | Marvin Attack affects decrypt path only; Hearth uses `rsa` only for key generation and PKCS#8 serialization — no decryption. |

Additionally, Dependabot and Snyk are configured to automatically detect and open PRs for
newly disclosed vulnerabilities in dependencies.

---

## Rate Limiting

The admin API enforces 100 requests per minute per authenticated admin. Adjust this at the
infrastructure level (API gateway, load balancer) if you need tighter limits for your
deployment.

---

## Audit Log Integrity

Hearth's audit log uses a SHA-256 hash chain for tamper evidence. Treat the audit log as
security-critical data:
- Back it up independently of the main data store.
- Monitor for gaps or out-of-order entries.
- Do not delete audit log entries to cover tracks — the hash chain will reveal the deletion.
