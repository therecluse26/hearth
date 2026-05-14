# Security Policy

## Supported Versions

Hearth is pre-1.0. Security fixes are applied to the `main` branch only. Once 1.0 ships, a supported-version table will be maintained here.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use one of the following channels:

- **GitHub Security Advisories (preferred):** Use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repository. This opens a private, encrypted channel between you and the maintainers. No GitHub account is required.
- **Email:** security@hearthdb.dev — PGP key available on request.

### What to include

Please provide:

1. A description of the vulnerability and the affected component.
2. Steps to reproduce or a proof-of-concept (even a partial one).
3. The potential impact as you understand it.
4. Any mitigations or workarounds you are aware of.

### Response SLA

| Severity | Acknowledgement | Patch target |
|---|---|---|
| Critical (CVSS ≥ 9.0) | 24 hours | 7 days |
| High (CVSS 7.0–8.9) | 48 hours | 14 days |
| Medium (CVSS 4.0–6.9) | 72 hours | 30 days |
| Low (CVSS < 4.0) | 5 business days | Next release |

We will keep you informed throughout the process and credit you in the release notes and CVE advisory unless you prefer to remain anonymous.

## Scope

The following are **in scope** for security reports:

| Component | Description |
|---|---|
| Storage encryption | AES-256-GCM three-tier envelope encryption (`src/storage/encryption.rs`) |
| JWT signing & verification | Ed25519 token issuance and validation (`src/identity/tokens.rs`) |
| Credential hashing | Argon2id password hashing and legacy migration (`src/identity/credentials.rs`) |
| Session management | Session lifecycle, TTL, revocation (`src/identity/engine.rs`) |
| SAML 2.0 | SP/IdP flows, XML signature validation (`src/identity/federation/saml/`) |
| OIDC / OAuth 2.0 | Relying party, authorization server, PKCE (`src/identity/federation/oidc.rs`, `src/protocol/web/`) |
| RBAC engine | Role composition, cycle detection, org scoping (`src/rbac/`) |
| Input validation | Centralised validator (`src/identity/validation.rs`) |
| WebAuthn / FIDO2 | Registration and authentication ceremonies (`src/identity/webauthn.rs`) |
| SCIM 2.0 | Provider auth, filter parsing, CRUD (`src/protocol/scim/`) |
| Webhook signing | HMAC-SHA256 delivery (`src/webhook/dispatcher.rs`) |
| Admin API | Auth and rate limiting (`src/protocol/admin_auth.rs`) |
| TLS | rustls configuration and hot-reload (`src/protocol/tls.rs`) |
| Audit log integrity | Hash-chain tamper detection (`src/audit/`) |

**Out of scope:**

- Vulnerabilities in third-party dependencies — please report those upstream. We actively track them via `cargo deny` and will address them promptly if they affect Hearth.
- Theoretical attacks with no practical exploitation path.
- Issues requiring physical access to the server or root/kernel-level compromise.
- Social engineering or phishing attacks.

## Safe Harbour

We consider security research conducted in good faith under this policy to be:

- Authorised in accordance with the Computer Fraud and Abuse Act (CFAA) and equivalent laws.
- Exempt from restrictions in our terms of service that would otherwise prohibit such research.

We will not pursue civil or criminal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption.
- Report findings through the channels above before public disclosure.
- Give us reasonable time to respond before public disclosure (90 days from initial report).

## Audit Status

A pre-release third-party security audit is in progress. This page will be updated with the audit report or public summary when available. An internal pre-audit assessment was completed with no critical findings across all in-scope components.

## Known Exceptions

| CVE / Advisory | Affected crate | Justification |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa` | Marvin Attack timing side-channel affects PKCS#1 v1.5 decryption only. Hearth uses the `rsa` crate exclusively for RSA key generation and PKCS#8 serialization — no decryption operations are performed. |

## Cryptographic Choices

For transparency, Hearth's core cryptographic primitive selections:

| Purpose | Algorithm | Library |
|---|---|---|
| At-rest encryption | AES-256-GCM | `ring` 0.17 |
| JWT signing | Ed25519 (EdDSA) | `ring` 0.17 |
| Password hashing | Argon2id (OWASP params: 19 MiB, 2 iterations, p=1) | `argon2` 0.5 |
| TLS | TLS 1.2 / 1.3 | `rustls` 0.23 |
| Webhook signing | HMAC-SHA256 | `ring` 0.17 |
| SCIM token comparison | SHA-256 + constant-time eq | `ring` + `subtle` |
