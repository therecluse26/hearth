# Hearth for AI Agents: Proper OAuth 2.0 for the Agentic Era

*Every major identity provider is now publishing their AI agent strategy. Ory Lumen, Auth0's "Agent Experience Score," Okta's MCP Server product. The emerging consensus is that AI agents need real OAuth 2.0 — not API keys, not shared secrets, not ad-hoc tokens. Hearth has shipped the required primitives. This post explains how to use them.*

---

## The problem agents have with identity

When a developer deploys an AI agent — whether it's a Claude Code session, an MCP server, or an autonomous workflow runner — that agent needs to call authenticated APIs. The naive solution is to hand the agent a long-lived API key or a static bearer token. This works until it doesn't:

- A static token gives the agent your full identity, not a scoped delegation.
- There's no standard revocation path when a token is compromised.
- There's no audit trail linking specific agent actions to specific tokens.
- The agent runs headlessly — there's no browser to redirect, no login form to render.

The right answer is OAuth 2.0, applied correctly to the headless agent pattern. Hearth ships the two grants that cover the full range of agent use cases: **Device Authorization Grant** for interactive approvals, and **client credentials** for fully autonomous agents.

---

## Grant 1: Device Authorization Grant (RFC 8628) — agents that need user approval

The Device Authorization Grant was designed for inputs-constrained devices (smart TVs, CLI tools) that can display a short code but can't open a browser. It maps directly to the AI agent case where a human needs to authorize what the agent is allowed to do.

**The flow:**

```
Agent → POST /device_authorization
        body: client_id=myagent&scope=files:read files:write

Server → { device_code, user_code: "BDFG-KMNT", verification_uri, expires_in: 300 }

Agent → display "Go to https://yourapp.com/activate and enter: BDFG-KMNT"

Agent → (polling) POST /token
                   grant_type=urn:ietf:params:oauth:grant-type:device_code
                   &device_code=<device_code>
                   &client_id=myagent

        → 428 authorization_pending  (keep polling)
        → 200 { access_token, refresh_token, expires_in }  (user approved)
```

The human reviews the requested scopes in a real browser session and approves or denies. The agent never sees the human's credentials. The resulting token is scoped to the exact permissions the human approved.

**Hearth endpoint:** `POST /device_authorization` (or `POST /realms/{realm}/device_authorization` for multi-tenant deployments). Polling via `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`.

User codes are generated from a 28-character unambiguous alphabet (no 0/O/I/1 confusion). Device codes are SHA-256 hashed at rest — the raw code is never stored. Rate limiting is enforced on the polling endpoint via `last_polled_at` tracking.

---

## Grant 2: client_credentials — fully autonomous agents

For agents that never interact with a human during execution — batch processors, background sync workers, scheduled data pipelines — the client credentials grant issues a service token directly to the agent using its registered `client_id` and `client_secret`.

```bash
# Register the agent as a confidential client
curl -X POST https://hearth.example.com/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"client_id":"pipeline-agent","client_secret":"...","grant_types":["client_credentials"],"scope":"data:read data:write"}'

# Agent fetches its token at startup
curl -X POST https://hearth.example.com/token \
  -d "grant_type=client_credentials&client_id=pipeline-agent&client_secret=...&scope=data:read"

# Returns: { "access_token": "...", "token_type": "bearer", "expires_in": 3600 }
```

Unlike a user session, client_credentials tokens are stateless — there's no associated session to expire. Hearth tracks issued JTIs (JWT IDs) for revocation: if a client secret is compromised, you can revoke the agent's token family immediately via the revocation endpoint, without waiting for expiry.

**Important:** client_credentials tokens include RBAC claims derived from the roles assigned to that client at registration time. A pipeline agent registered with `data:read` cannot escalate to `data:write` by requesting a broader scope at token-fetch time — the server clamps to the intersection.

---

## Tokens: Ed25519, compact, fast

Every token Hearth issues is signed with Ed25519. This matters for agents because:

- **Ed25519 verification is ~10µs.** An agent that validates 10,000 tokens per second spends less than 100ms on verification alone. RSA-2048 verification is ~100µs — one order of magnitude slower.
- **Ed25519 keys are 32 bytes.** RSA public keys are 256–512 bytes. Every JWKS fetch is smaller. Every verification is a smaller key comparison.
- **Determinism is safe with unique JTIs.** Ed25519 is deterministic (same private key + same message = same signature). Hearth adds a `jti` claim to every token to guarantee uniqueness, preventing signature replay across identical-claim tokens.

Per-realm signing keys are stored as PKCS#8 DER, lazily loaded, and cached in memory. An agent validating tokens against Hearth's JWKS endpoint can cache the public key and verify locally with zero network calls on the hot path.

---

## Grant families and credential revocation

When an agent uses a refresh token to rotate its credentials, Hearth links issued tokens in a **grant family** — a UUID tracked with the current refresh token hash. This enables:

- **Rotation detection:** if a refresh token is presented that doesn't match the current hash for its family, Hearth treats it as theft evidence and revokes the entire family immediately. A compromised agent credential that attempts rotation is self-revoking.
- **Full revocation:** revoke the grant family to invalidate all tokens the agent has issued without touching unrelated sessions.

For client_credentials flows (sessionless), revocation is JTI-based: issued token IDs are stored in a blocklist keyed as `oauth:revjti:{jti}`. Token introspection returns `active: false` immediately after revocation.

---

## Multi-tenant isolation with realms

Hearth's realm model maps cleanly to multi-agent deployments. Each realm is an isolated identity namespace with its own signing key, its own client registry, and its own RBAC configuration.

Common patterns:

| Realm | Contains |
|-------|---------|
| `internal` | First-party agents and services |
| `partners` | Third-party integrations with constrained scopes |
| `staging` | Agent credentials for pre-production environments |

Agents in one realm cannot use tokens from another. Per-realm client_credentials flows are available at `POST /realms/{realm}/token`.

---

## What Hearth does not do (yet)

Honest gap disclosure:

- **JWT Authorization Grant (RFC 7523) / SPIFFE**: Keycloak 26.6 now supports obtaining tokens using externally-signed JWTs from Kubernetes service accounts or SPIFFE SVIDs — eliminating shared secrets entirely for workload-identity use cases. Hearth's client_credentials flow requires a client secret. This is a known gap for Kubernetes-native agent deployments.
- **DPoP (Demonstration of Proof-of-Possession)**: Auth0 positions DPoP heavily for agent auth. Hearth does not currently implement DPoP binding. Bearer tokens remain the only supported mechanism.
- **MCP-native token metadata**: The MCP specification is evolving. Hearth does not yet ship MCP-specific token introspection extensions or agent-oriented metadata claims. The standard OAuth 2.0 + OIDC surface is what you get today.

These are engineering items, not design decisions. The OAuth 2.0 substrate Hearth ships is the correct foundation — adding RFC 7523, DPoP, and richer agent metadata is additive work on top of it.

---

## Quick start: issuing your first agent token

```bash
# 1. Start Hearth in dev mode
cargo build --release
./target/release/hearth serve --dev

# 2. Bootstrap (creates default realm + admin token)
curl -X POST http://127.0.0.1:8420/admin/bootstrap

# 3. Register an agent client
curl -X POST http://127.0.0.1:8420/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-agent",
    "client_secret": "agent-secret-change-me",
    "grant_types": ["client_credentials"],
    "scope": "read write"
  }'

# 4. Agent fetches its token
curl -X POST http://127.0.0.1:8420/token \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret-change-me&scope=read"

# Decode the JWT: verify Ed25519 signature, inspect `roles`, `permissions`, `scope` claims
```

For interactive agent approval via Device Authorization Grant, replace step 4 with the `POST /device_authorization` flow described above.

---

## Why self-hosted matters for agents

The AI agent ecosystem is still converging on trust boundaries. Which systems can the agent call? Which tokens should the orchestrator trust? Self-hosting the identity layer means you control the signing key, the token policy, the audit log, and the revocation infrastructure — none of it transits a cloud provider's control plane.

Hearth is a single binary. There are no external dependencies, no database to provision, no cluster to manage. An agent fleet's entire identity infrastructure can run as a sidecar or on a dedicated small VM at sub-millisecond token validation latency.

---

*All technical claims in this post are verified against the Hearth source code as of [2026-05-15]. Device Authorization Grant: `src/protocol/http.rs:472`, `src/identity/engine.rs:4487`. Client credentials: `src/protocol/http.rs:1622`. Grant families and JTI revocation: `src/identity/oidc.rs`. Ed25519 signing: `src/identity/tokens.rs`.*
