# Agent Authentication & Authorization

## Purpose

This document specifies how Hearth authenticates, authorizes, and audits AI agents — autonomous software entities that act on behalf of users, invoke tools, and collaborate with other agents. It extends Hearth's existing OAuth 2.0, OIDC, and claims-based RBAC authorization (see [AUTHORIZATION.md](./AUTHORIZATION.md)) with agent-specific primitives for delegation, scope attenuation, proof-of-possession, and human-in-the-loop approval.

Terminology follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** carry their standard meaning. MUST-level rules block merge with no exceptions. SHOULD-level rules require a PR comment explaining the deviation.

### Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md) — layer structure, hot path rules, security baseline, storage engine.
- [AUTHORIZATION.md](./AUTHORIZATION.md) — normative spec for Hearth's RBAC model (roles, groups, permissions, JWT claims). Agent permissions extend this model.
- [TESTING.md](./TESTING.md) — eight testing layers and verification strategy.
- [VISION.md](../vision/VISION.md) — design rationale and competitive positioning.

### Definitions

| Term | Meaning |
|------|---------|
| **Agent** | An autonomous software entity with its own identity, registered in Hearth, that performs actions programmatically. Not a user. Not an OAuth client (though it may use OAuth flows). |
| **Delegation** | A user or agent granting an agent permission to act on its behalf, with bounded scope and duration. |
| **Tool** | A discrete capability an agent can invoke (e.g., `send_email`, `search_files`, `create_order`). Identified by a name; permissions over it are expressed as RBAC permission strings (e.g. `tool.send_email.invoke`). |
| **Delegation chain** | An ordered list of principals through which authority was delegated: `user:U → agent:A → agent:B`. Each hop attenuates scope. |
| **Agent Card** | A JSON metadata document describing an agent's capabilities, authentication requirements, and endpoint URL. Served at a well-known path per the A2A protocol. |
| **MCP** | Model Context Protocol — a standard for AI agents to connect to tool servers. |
| **AAT** | Attenuating Authorization Token — a JWT that any holder can narrow but never widen. |
| **DPoP** | Demonstrating Proof-of-Possession — a mechanism binding tokens to an asymmetric key pair. |
| **PRM** | Protected Resource Metadata — a discovery document describing a resource server's authorization requirements. |

---

## 1. Agent Identity

### 1.1 Agent as a First-Class Entity

Agents **MUST** be a distinct entity type in Hearth, separate from users and OAuth clients. An agent has its own identity lifecycle, credential set, capability declarations, and audit trail.

**Rationale:** OAuth clients authenticate applications; users authenticate humans. Agents are neither — they are autonomous actors with delegated authority. Collapsing agents into OAuth clients loses the ability to express delegation chains, per-agent policy, and agent-specific audit context.

### 1.2 Agent Entity

An agent record **MUST** contain:

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `AgentId` (newtype UUID, prefix `agt_`) | Unique identifier. |
| `realm_id` | `RealmId` | Owning realm. |
| `owner_id` | `UserId` or `OrganizationId` | The human or organization that registered this agent. |
| `display_name` | String (1–256 chars) | Human-readable name. |
| `description` | String (optional, max 2048 chars) | What the agent does. |
| `capabilities` | List of capability URIs | Declared capabilities (see [Section 1.4](#14-capabilities)). |
| `status` | Enum: `Active`, `Suspended`, `Revoked` | Lifecycle state. |
| `max_delegation_depth` | Integer (1–10, default 1) | Maximum hops this agent may delegate further. |
| `created_at` | Timestamp (UTC microseconds) | Creation time. |
| `updated_at` | Timestamp (UTC microseconds) | Last modification. |

**Rules:**

- `AgentId` **MUST** be a distinct newtype following the conventions in [ARCHITECTURE.md Section 12.1](./ARCHITECTURE.md#121-newtype-ids). It **MUST NOT** implement `Deref`.
- Every agent **MUST** belong to exactly one realm. All storage keys **MUST** be realm-prefixed per [ARCHITECTURE.md Section 7](./ARCHITECTURE.md#7-multi-tenancy).
- An agent's `owner_id` **MUST** reference an existing user or organization within the same realm.
- Agent status transitions **MUST** be: `Active → Suspended → Active` (reversible) and `Active|Suspended → Revoked` (terminal). Revoked agents **MUST NOT** authenticate or be re-activated.
- Agent deletion **MUST** cascade: revoke all active tokens, remove all RBAC role assignments where the agent is the subject, remove the agent from any groups, delete all credentials, and emit an audit event.

### 1.3 Agent Registration API

The protocol layer **MUST** expose CRUD endpoints for agents:

| Operation | Method | Path |
|-----------|--------|------|
| Create | POST | `/v1/agents` |
| Get | GET | `/v1/agents/{agent_id}` |
| List | GET | `/v1/agents` |
| Update | PATCH | `/v1/agents/{agent_id}` |
| Delete | DELETE | `/v1/agents/{agent_id}` |

**Rules:**

- Agent creation **MUST** require the caller to be an authenticated user or an admin with `agent:create` permission.
- The owner **MUST** be set to the authenticated user unless the caller is an admin (admins **MAY** specify a different owner).
- List endpoints **MUST** support filtering by `owner_id`, `status`, and capability.
- Pagination **MUST** follow the same cursor-based pattern used by existing list endpoints.

### 1.4 Capabilities

Capabilities declare what an agent is designed to do. They are informational metadata (not enforcement) — enforcement is handled by RBAC permission grants (see [Section 5](#5-tool-level-permissions)).

- Capabilities **MUST** be expressed as URIs following the pattern: `urn:hearth:capability:{domain}:{action}` (e.g., `urn:hearth:capability:email:send`, `urn:hearth:capability:files:read`).
- Capability URIs **SHOULD** align with the tool names registered in the realm's tool registry.
- Agents **MAY** declare zero capabilities (unconstrained agents are governed entirely by their RBAC permission grants).

### 1.5 Agent Credentials

An agent **MUST** authenticate using one or more of the following credential types:

| Credential Type | Storage | Use Case |
|----------------|---------|----------|
| API key | SHA-256 hash of key; plaintext never stored | Simple server-to-server integrations |
| Asymmetric key pair (Ed25519 or P-256) | Public key stored; private key held by agent | DPoP-bound tokens, JWT assertions |
| mTLS client certificate | X.509 certificate chain; CA fingerprint | Workload identity, SPIFFE SVIDs |

**Rules:**

- API keys **MUST** be generated with at least 256 bits of entropy.
- API keys **MUST** be shown to the caller exactly once at creation time. Only the SHA-256 hash is stored.
- API key comparison **MUST** use constant-time comparison per [ARCHITECTURE.md Section 8.2](./ARCHITECTURE.md#82-cryptographic-primitives).
- Asymmetric keys **MUST** use Ed25519 by default, aligning with Hearth's existing signing infrastructure. P-256 (ES256) **MAY** be supported for ecosystem compatibility.
- An agent **MAY** have multiple active credentials of different types.
- Credential rotation **MUST** allow overlapping validity windows (add new, then revoke old).

### 1.6 Agent Cards (A2A Protocol)

Hearth **SHOULD** serve an Agent Card for each registered agent, enabling discovery by other agents per the A2A protocol.

- Agent Cards **MUST** be served at `/.well-known/agent.json?agent_id={agent_id}` for a specific agent, or at `/.well-known/agent.json` for the realm's primary agent.
- The Agent Card **MUST** include: `name`, `description`, `url` (agent endpoint), `authentication` (supported schemes), `capabilities` (skill list).
- Agent Cards **MUST NOT** expose internal implementation details, credential material, or the agent's full permission set.
- Agent Cards **SHOULD** include a `version` field for cache busting.

---

## 2. MCP Authorization Server

### 2.1 Overview

Hearth **MUST** function as an OAuth 2.1-compliant authorization server for the MCP ecosystem. MCP clients discover Hearth via Protected Resource Metadata, obtain scoped tokens, and present them to MCP tool servers.

### 2.2 OAuth 2.1 Baseline

Hearth's existing OAuth 2.0 implementation **MUST** be extended to meet OAuth 2.1 requirements:

- PKCE **MUST** be required for all authorization code flows (already implemented).
- The implicit grant **MUST NOT** be supported (already enforced).
- Refresh token rotation **MUST** be enforced (already implemented via grant families).
- Bearer tokens **SHOULD** be sender-constrained via DPoP (see [Section 6](#6-proof-of-possession-dpop)) when the client supports it.

### 2.3 Resource Indicators (RFC 8707)

MCP clients need tokens scoped to a specific tool server. Hearth **MUST** support the `resource` parameter per RFC 8707.

**Rules:**

- Authorization requests and token requests **MUST** accept a `resource` parameter containing the URI of the target MCP server.
- The `resource` value **MUST** match a registered protected resource (see [Section 2.5](#25-protected-resource-registration)).
- Resulting access tokens **MUST** include an `aud` (audience) claim matching the requested resource URI.
- If no `resource` parameter is provided, the token **MUST** be scoped to Hearth itself (the default audience).
- Multiple `resource` parameters in a single request **MAY** be supported; each produces a separate token.

### 2.4 Protected Resource Metadata (RFC 9728)

MCP tool servers advertise their authorization requirements via a discovery document. Hearth **MUST** support this discovery flow.

**Rules:**

- MCP servers registered with Hearth **MUST** have their metadata available at `/.well-known/oauth-protected-resource` on the MCP server's origin. Hearth itself **MUST** publish its own PRM document at this path.
- The PRM document **MUST** include: `resource` (server URI), `authorization_servers` (array containing Hearth's issuer URL), `scopes_supported`, `bearer_methods_supported`.
- Hearth's OIDC discovery document (`.well-known/openid-configuration`) **MUST** include `resource_indicators_supported: true`.

### 2.5 Protected Resource Registration

Realms register their MCP tool servers as protected resources in Hearth.

| Field | Type | Description |
|-------|------|-------------|
| `resource_id` | UUID | Unique identifier. |
| `resource_uri` | URI | The canonical URI of the MCP server (used as `aud` in tokens). |
| `display_name` | String | Human-readable name. |
| `scopes` | List of strings | Scopes this resource supports. |
| `required_claims` | List of strings | Claims the resource requires in tokens. |

**Rules:**

- Resource URIs **MUST** be unique within a realm.
- Resource URIs **MUST** use HTTPS in production. HTTP **MAY** be permitted in `--dev` mode.
- Deletion of a protected resource **MUST** revoke all outstanding tokens scoped to that resource.

### 2.6 MCP Scope Strings

Tokens issued for MCP servers **SHOULD** use granular scope strings aligned with MCP's capability model:

| Scope | Meaning |
|-------|---------|
| `mcp:tools:invoke` | Invoke tools on the MCP server |
| `mcp:tools:list` | List available tools |
| `mcp:resources:read` | Read MCP resources |
| `mcp:resources:write` | Write MCP resources |
| `mcp:prompts:read` | Read prompt templates |

- Custom scopes **MAY** be registered per protected resource.
- Scope strings **MUST** follow the pattern `{namespace}:{category}:{action}`.

### 2.7 Dynamic Client Registration

Hearth's existing Dynamic Client Registration (RFC 7591) **MUST** be extended to support agent clients:

- Registration requests **MAY** include `agent_id` to associate the OAuth client with a registered agent.
- If `agent_id` is provided, the client **MUST** inherit the agent's authentication requirements (e.g., DPoP-required).
- Agents **SHOULD** use Dynamic Client Registration to auto-register when connecting to a new Hearth instance, reducing manual configuration.

---

## 3. Delegated Authorization

### 3.1 Overview

When an agent acts on behalf of a user, the resulting token **MUST** encode both the user's identity (the delegating principal) and the agent's identity (the acting principal). This dual-identity model is essential for authorization decisions, audit, and accountability.

### 3.2 On-Behalf-Of Extension (OBO)

Hearth **MUST** implement the OAuth 2.0 On-Behalf-Of extension per draft-oauth-ai-agents-on-behalf-of-user-02.

**Authorization Request:**

- The authorization request **MUST** accept a `requested_actor` parameter identifying the agent that will act on behalf of the user: `requested_actor=agent:{agent_id}`.
- The authorization server **MUST** verify that the referenced agent exists, is active, and has permission to act for the requesting client's context.
- The consent screen **MUST** clearly display which agent is requesting delegated access and what scopes it requests.

**Token Request:**

- The token request **MUST** accept an `actor_token` parameter: a JWT assertion signed by the agent's key, proving the agent's identity during code exchange.
- The `actor_token` **MUST** include claims: `iss` (agent identifier), `sub` (agent identifier), `aud` (Hearth token endpoint), `iat`, `exp` (short-lived, max 5 minutes), `jti` (unique, for replay protection).

**Resulting Token:**

- The access token **MUST** include the `act` (actor) claim per RFC 8693 Section 4.1:

  ```
  {
    "sub": "user:U",
    "act": {
      "sub": "agent:A"
    },
    "scope": "read:files send:email",
    "aud": "https://mcp.example.com"
  }
  ```

- The `act` claim **MUST** be a JSON object containing at minimum `sub` (the acting agent's identifier).
- The `act` claim **MAY** be nested for multi-hop delegation chains (see [Section 3.4](#34-delegation-chains)).

### 3.3 Token Exchange (RFC 8693)

Hearth **MUST** implement the token exchange grant type (`urn:ietf:params:oauth:grant-type:token-exchange`) per RFC 8693.

**Rules:**

- The `subject_token` **MUST** be the user's access token (proving the user's identity and granted scopes).
- The `actor_token` **MUST** be the agent's JWT assertion (proving the agent's identity).
- The `subject_token_type` **MUST** be `urn:ietf:params:oauth:token-type:access_token`.
- The `actor_token_type` **MUST** be `urn:ietf:params:oauth:token-type:jwt`.
- The resulting token's scope **MUST** be the intersection of: the subject token's scope, the agent's permitted scopes (derived from its own RBAC permission claims), and the `scope` parameter in the exchange request.
- The resulting token **MUST** carry the `act` claim documenting the delegation.
- The resulting token's lifetime **MUST NOT** exceed the subject token's remaining lifetime.

### 3.4 Delegation Chains

When agent A delegates to agent B, the delegation chain grows. Hearth **MUST** support and enforce multi-hop delegation.

**Token Structure:**

- A two-hop chain (user → agent A → agent B) **MUST** produce:

  ```
  {
    "sub": "user:U",
    "act": {
      "sub": "agent:B",
      "act": {
        "sub": "agent:A"
      }
    }
  }
  ```

- The outermost `act.sub` is the immediate actor. Inner `act` claims record the delegation history.

**Enforcement:**

- Delegation depth **MUST** be bounded by the agent's `max_delegation_depth` field (see [Section 1.2](#12-agent-entity)). A token exchange that would exceed this depth **MUST** be rejected.
- Each hop in the chain **MUST** attenuate scope — the resulting token's scope **MUST** be a subset of the parent token's scope. Scope can only narrow, never widen.
- Each hop **MUST** attenuate lifetime — the resulting token's expiry **MUST NOT** exceed the parent token's expiry.
- The delegation chain **MUST** be recorded in the audit log for every token issuance (see [Section 12](#12-observability--audit)).

### 3.5 Consent Management

Users **MUST** explicitly approve which agents can act on their behalf.

**Rules:**

- First-time delegation **MUST** require explicit user consent via the authorization flow.
- Consent records **MUST** store: user, agent, granted scopes, timestamp, and expiry.
- Users **MUST** be able to view and revoke active agent delegations via the API and admin UI.
- Revoking consent **MUST** immediately invalidate all tokens issued under that delegation (revoke the grant family).
- Consent **SHOULD** support time-bounded grants (e.g., "allow for 24 hours").

---

## 4. Scope Attenuation

### 4.1 Overview

Attenuating Authorization Tokens (AATs) allow any token holder to derive a more restrictive token without contacting the authorization server. This is critical for multi-hop agent delegation: each agent in the chain can narrow permissions before passing tokens downstream.

### 4.2 AAT Structure

Hearth **SHOULD** support AATs per draft-niyikiza-oauth-attenuating-agent-tokens.

**Token Claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `tools` | Array of tool permission objects | Allowed tool invocations with argument constraints. |
| `aat_parent` | String (JTI reference) | Reference to the parent token from which this AAT was derived. |
| `aat_chain` | Array of JTI strings | Ordered list of token IDs in the attenuation chain. |

**Tool Permission Object:**

| Field | Type | Description |
|-------|------|-------------|
| `tool` | String (tool URI) | The tool this permission applies to. |
| `actions` | Array of strings | Allowed actions (e.g., `invoke`, `list`, `describe`). |
| `constraints` | Object (optional) | Argument-level constraints (e.g., `{"max_results": 100}`). |

### 4.3 Derivation Rules

- Any holder of an AAT **MAY** derive a child AAT offline (no round-trip to Hearth).
- The child **MUST** have equal or fewer `tools` entries than the parent.
- The child **MUST** have equal or narrower `constraints` for each tool.
- The child **MUST** have equal or shorter lifetime (`exp`).
- The child **MUST** have equal or fewer scopes.
- The child **MUST NOT** add tools, widen constraints, extend lifetime, or add scopes. Violation of this invariant **MUST** cause token validation to fail.
- The child **MUST** be signed by the same key that signed the parent (or by a key authorized for derivation via the `cnf` claim).

### 4.4 Validation

- Hearth **MUST** validate the full attenuation chain when an AAT is presented.
- Validation **MUST** verify: each `aat_parent` exists in the chain, each child's permissions are a subset of its parent's, and no chain link has been revoked.
- Chain validation **SHOULD** be optimized for the common case (depth 1–2). Chains deeper than 5 **MAY** incur additional latency.
- Revocation of any token in the chain **MUST** invalidate all descendants.

---

## 5. Tool-Level Permissions

### 5.1 Overview

Tool invocation permissions are expressed as RBAC permission strings granted to an agent via role assignments. This reuses Hearth's existing RBAC engine (see [AUTHORIZATION.md](./AUTHORIZATION.md)) with no agent-specific authorization machinery: agents are treated as principals like users, receiving role assignments that grant permissions in the standard way.

### 5.2 Permission Convention

Tool permissions follow a naming convention in the realm's permission namespace:

| Permission pattern | Semantics |
|--------------------|-----------|
| `tool.{name}.invoke` | Agent may invoke the tool without human approval. |
| `tool.{name}.invoke_with_approval` | Agent may invoke the tool only with human approval (see [Section 9](#9-human-in-the-loop-authorization)). |
| `tool.{name}.deny` | Agent is explicitly denied access. Takes precedence over other grants. |

Tool groups use the same pattern with a `toolgroup.{name}.*` prefix. A role that grants `toolgroup.email_suite.invoke` conceptually gives access to every tool in the group; tool-to-group membership is recorded as a realm-config mapping (in the tool registry), not as RBAC state, because this is a static deployment concern rather than a per-principal grant.

### 5.3 Assigning Permissions

Agents receive tool permissions like any other principal: an admin creates a role that includes the relevant `tool.*` permissions, then assigns it to the agent (or to a group the agent belongs to). The permissions appear in the agent's resolved claim set at token issuance per `AUTHORIZATION.md § 3`.

Example role:

```yaml
roles:
  - name: email.editor
    permissions:
      - tool.send_email.invoke
      - tool.search_emails.invoke
      - tool.delete_email.invoke_with_approval
```

Assigning `email.editor` to an agent gives it direct send/search access and approval-gated delete access.

**Rules:**

- Agent permission checks **MUST** use the agent's access-token permissions claim, not a separate API call. Resolution runs at token issuance; no network round trip per tool invocation.
- `tool.{name}.deny` in the agent's resolved claim set **MUST** cause tool invocation to fail, even if `tool.{name}.invoke` is also present. Evaluation order: check deny first; deny wins.
- Tool group membership is a realm-config concept, not a per-principal grant. Tools can be added to or removed from a group via realm config without rewriting RBAC state.
- Argument-level constraints **MUST NOT** be encoded in the permission string itself. Permission strings answer "may the agent invoke this tool at all"; argument-level enforcement is handled by AAT validation (see [Section 4](#4-scope-attenuation)).
- The `delegate` concept (agent A delegating to agent B) is handled via token exchange per [Section 3.3](#33-token-exchange-rfc-8693); there is no `tool.*.delegate` permission. An agent's ability to delegate to another agent is determined by its own permission claims being a superset of what it attempts to delegate.

### 5.4 Scope Intersection at Delegation

When an agent requests a delegated token (via OBO or token exchange), the resulting scope **MUST** be computed as:

```
effective_scope = intersection(
    user_granted_scopes,          -- what the user consented to
    agent_permitted_scopes,       -- what the agent is allowed to do, from its RBAC claims
    requested_scope               -- what the agent asked for
)
```

- If the intersection is empty, the token request **MUST** be rejected with `invalid_scope`.
- The permission check **MUST** be performed at token issuance time, not at resource access time (fail-fast).
- Resource servers **SHOULD** additionally validate scopes at access time for defense-in-depth.

---

## 6. Proof-of-Possession (DPoP)

### 6.1 Overview

Bearer tokens can be stolen and replayed. Agents operating in untrusted environments **SHOULD** use sender-constrained tokens via DPoP (RFC 9449), binding tokens to the agent's asymmetric key.

### 6.2 DPoP Flow

1. The agent generates an asymmetric key pair (Ed25519 or P-256) or uses a registered key.
2. On token request, the agent includes a `DPoP` header containing a DPoP proof JWT signed by its private key.
3. Hearth validates the DPoP proof and issues an access token with a `cnf` (confirmation) claim containing `jkt` (JWK thumbprint) of the agent's public key.
4. On resource access, the agent presents both the access token and a fresh DPoP proof.
5. The resource server validates: the DPoP proof signature matches the `cnf.jkt` in the token, the `htm` (HTTP method) and `htu` (HTTP URI) match the request, and the `ath` (access token hash) matches.

### 6.3 Rules

- Hearth **MUST** support DPoP proofs per RFC 9449.
- DPoP proof JWTs **MUST** use `typ: dpop+jwt` in the JOSE header.
- DPoP proof JWTs **MUST** include: `jti` (unique), `htm` (HTTP method), `htu` (target URI), `iat` (issued at). The `ath` (access token hash) claim **MUST** be included when the proof accompanies a resource request.
- DPoP proof `iat` **MUST** be within a configurable clock skew window (default: 60 seconds).
- DPoP `jti` values **MUST** be tracked for replay prevention. The replay window **MUST** match the clock skew window.
- Access tokens bound via DPoP **MUST** use token type `DPoP` (not `Bearer`).
- Hearth **MUST** include a `DPoP-Nonce` response header to enable server-provided nonces for tighter replay protection. Clients **MUST** include the server nonce in subsequent DPoP proofs when provided.
- Ed25519 **MUST** be supported for DPoP keys, aligning with Hearth's existing signing infrastructure per [ARCHITECTURE.md Section 8.1](./ARCHITECTURE.md#81-token-validation-and-signing). P-256 (ES256) **SHOULD** also be supported.
- DPoP **SHOULD** be required for agents by default. It **MAY** be made optional per realm configuration for backward compatibility.

### 6.4 DPoP for Delegation Chains

When a delegated token is re-bound at each hop:

- Agent A obtains a DPoP-bound token from the user's delegation.
- Agent A performs a token exchange, presenting its DPoP proof. The resulting token is bound to agent B's key (agent B provides its public key in the exchange request).
- Each hop re-binds the token to the next agent's key. The previous agent can no longer use the token.

---

## 7. Intent Binding

### 7.1 Overview

Intent binding constrains a token to a specific operation or workflow, preventing misuse even if the token is intercepted. This goes beyond scope (what you can do) to specify intent (what you will do right now).

### 7.2 Agentic JWT Claims

Tokens issued for agent operations **MAY** include intent-binding claims:

| Claim | Type | Description |
|-------|------|-------------|
| `agent_intent` | String | Description of the intended action (e.g., `"send quarterly report to finance team"`). |
| `agent_workflow_id` | String | Identifier for the multi-step workflow this token belongs to. |
| `agent_step` | Integer | Current step in the workflow (for sequential operations). |
| `agent_checksum` | String | SHA-256 hash of the agent's code or configuration at issuance time. |
| `tool_binding` | Array of strings | Specific tools this token is valid for (stricter than scope). |

### 7.3 Rules

- Intent-binding claims are **OPTIONAL** — they provide defense-in-depth beyond scope and RBAC permission enforcement.
- When `tool_binding` is present, the resource server **MUST** reject requests for tools not in the list, even if the scope would otherwise allow them.
- When `agent_checksum` is present, runtime environments **SHOULD** verify the agent's code integrity matches the recorded checksum.
- `agent_workflow_id` enables correlation of related token uses across audit logs.
- Intent claims **MUST NOT** be used as the sole authorization mechanism — they supplement permission and scope checks, not replace them.

---

## 8. Agent-to-Agent Trust

### 8.1 Overview

Multi-agent systems require agents to discover each other, establish mutual trust, and exchange capability information. Hearth provides the trust infrastructure for agent-to-agent interactions within and across realms.

### 8.2 Agent Discovery

- Hearth **MUST** expose an agent registry API: `GET /v1/agents?capability={uri}&status=active`.
- Agents **SHOULD** be discoverable by capability, realm, and tag.
- Agent Cards (see [Section 1.6](#16-agent-cards-a2a-protocol)) serve as the discovery document for individual agents.
- A realm-level agent directory **MAY** be exposed at `/.well-known/agents` listing all public agents in the realm.

### 8.3 Mutual Authentication

When agent A calls agent B:

1. Agent A obtains a token from Hearth scoped to agent B (using `resource` indicator or `aud` claim).
2. Agent A presents the token to agent B with a DPoP proof.
3. Agent B validates the token against Hearth's JWKS endpoint and verifies the DPoP proof.
4. If agent B requires it, mutual authentication is established: agent B also presents its identity to agent A via a reciprocal token or mTLS.

**Rules:**

- Agent-to-agent tokens **MUST** include `aud` (audience) matching the target agent's identifier or endpoint URL.
- Agent-to-agent tokens **SHOULD** be short-lived (max 5 minutes) to limit replay windows.
- mTLS **MAY** be used as an alternative to DPoP for agent-to-agent authentication, particularly in infrastructure contexts.

### 8.4 Cross-Realm Agent Trust

Agents from different realms **MAY** interact if cross-realm trust is configured.

**Rules:**

- Cross-realm trust **MUST** be explicitly configured by realm administrators. No implicit trust.
- Trust policies **MUST** specify: source realm, target realm, allowed capabilities, and expiry.
- Tokens for cross-realm interactions **MUST** include both the issuing realm and the target realm in their claims.
- Cross-realm requests **MUST** be rate-limited independently from intra-realm requests.
- Cross-realm trust policies **MUST** be auditable.

### 8.5 Transaction Tokens

For single agent-to-agent transactions, Hearth **SHOULD** support short-lived, non-replayable transaction tokens per draft-oauth-transaction-tokens-for-agents.

**Rules:**

- Transaction tokens **MUST** be single-use (bound to a specific transaction ID).
- Transaction tokens **MUST** expire within 60 seconds.
- Transaction tokens **MUST** include: `txn` (transaction ID), `sub` (requesting agent), `aud` (target agent), `act` (delegation context if acting on behalf of a user).
- The `txn` claim **MUST** be tracked for replay prevention.

---

## 9. Human-in-the-Loop Authorization

### 9.1 Overview

Some agent actions are too sensitive for automatic authorization. Hearth **MUST** support step-up authorization flows where human approval is required before an agent can proceed.

### 9.2 Approval-Required Permissions

The `tool.{name}.invoke_with_approval` permission (see [Section 5.2](#52-permission-convention)) triggers the human-in-the-loop flow:

1. Agent's access token contains `tool.X.invoke_with_approval` but NOT `tool.X.invoke`.
2. Agent attempts to invoke tool X. Runtime/SDK observes approval-required permission and creates an approval request instead of failing.
3. The designated approver(s) are notified.
4. Approver grants or denies the request.
5. If granted, a time-boxed capability token is issued carrying `tool.X.invoke` for the approved invocation only.

### 9.3 Approval Requests

An approval request **MUST** contain:

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | UUID | Unique identifier. |
| `agent_id` | `AgentId` | The requesting agent. |
| `tool` | String | The tool being requested. |
| `action` | String | The specific action (e.g., `invoke`). |
| `context` | Object | Agent-provided context (why it needs this, what it will do). |
| `delegation_chain` | Array | Full delegation chain at time of request. |
| `requested_at` | Timestamp | When the request was made. |
| `expires_at` | Timestamp | When the request expires if not acted upon (default: 1 hour). |
| `status` | Enum: `Pending`, `Approved`, `Denied`, `Expired` | Current state. |

### 9.4 Approval Policies

Realms **MUST** be able to configure approval policies per tool and per agent:

| Policy | Behavior |
|--------|----------|
| `auto_approve` | Agent may invoke without human approval. Expressed as `tool.{name}.invoke` permission in the agent's role. |
| `require_approval` | Agent must obtain human approval. Expressed as `tool.{name}.invoke_with_approval` permission in the agent's role. |
| `deny` | Agent may never invoke, regardless of approval. Expressed as `tool.{name}.deny` permission in the agent's role; takes precedence over `invoke`. |

**Rules:**

- Policies **SHOULD** support risk-based configuration: different tools get different policies based on sensitivity.
- Approved requests **MUST** issue a capability token with a configurable TTL (default: 5 minutes, max: 1 hour).
- The capability token **MUST** be scoped to the specific tool and action that was approved.
- Expired requests **MUST** be treated as denied. Agents **MUST** create a new request to retry.
- Approvers **MUST** be identified by RBAC permissions: an approver is any principal whose token claims include the permission `approval.{request_id}.approve` (or a broader role that grants it, e.g. `approval.tool.send_email.approve` for any approval request targeting that tool). Realm config declares which permissions govern which approval domains.

### 9.5 Notification

- Hearth **SHOULD** support webhook notifications when approval requests are created.
- The webhook payload **MUST** include: request ID, agent identity, tool requested, delegation chain, and a URL to approve/deny.
- Webhook endpoints **MUST** be configured per realm.
- Hearth **SHOULD** also support notification via the admin UI (polling or Server-Sent Events).

---

## 10. Continuous Access Evaluation

### 10.1 Overview

Traditional token-based authorization makes a binary decision at issuance time. Continuous Access Evaluation (CAEP) extends this with real-time risk signals that can revoke or restrict agent access mid-session.

### 10.2 Risk Signals

Hearth **SHOULD** emit and consume the following risk signals:

| Signal | Source | Effect |
|--------|--------|--------|
| Agent anomalous rate | Rate monitoring | Suspend agent, revoke tokens |
| User session revoked | User action | Revoke all delegated agent tokens |
| Agent owner deactivated | Admin action | Suspend all owned agents |
| Realm suspended | Admin action | Revoke all realm agent tokens |
| DPoP key compromise reported | Agent or admin | Revoke tokens bound to compromised key |
| Cross-realm trust revoked | Admin action | Revoke all cross-realm agent tokens |

### 10.3 Signal Delivery

- Risk signals **SHOULD** be delivered via Hearth's audit event stream. Subscribers filter for signal events and act (revoke, suspend, notify).
- External consumers **MAY** receive signals via the Shared Signals Framework (SSF) using Server-Sent Events or webhook push.
- Signal delivery **MUST** be best-effort with at-least-once semantics. Consumers **MUST** handle duplicate signals idempotently.

### 10.4 Token Revocation on Signal

- When a risk signal triggers revocation, all affected tokens **MUST** be invalidated within the signal propagation window.
- For session-based tokens: the session is revoked, and subsequent validation fails immediately.
- For sessionless tokens (e.g., `client_credentials`): the JTI is added to the revocation blocklist per existing OAuth implementation.
- For DPoP-bound tokens: the key thumbprint is added to a blocklist, invalidating all tokens bound to that key.

### 10.5 Rules

- CAEP signal evaluation **MUST NOT** add latency to the hot path (see [ARCHITECTURE.md Section 3](./ARCHITECTURE.md#3-hot-path-rules)). Revocation is applied asynchronously; the hot path checks the pre-computed revocation state.
- Signal evaluation **SHOULD** be configurable per realm (some realms may not want aggressive auto-revocation).
- All signal-triggered actions **MUST** be recorded in the audit log with the triggering signal as context.

---

## 11. Workload Identity

### 11.1 Overview

In infrastructure contexts (Kubernetes, cloud platforms), agents authenticate as workloads rather than as users or API key holders. Hearth **SHOULD** support SPIFFE-compatible workload identity for agent authentication.

### 11.2 SPIFFE SVIDs

- Agents **MAY** authenticate using X.509 SVIDs (SPIFFE Verifiable Identity Documents).
- The SPIFFE ID **MUST** follow the format: `spiffe://{trust_domain}/agent/{agent_id}`.
- Hearth **MAY** act as a SPIFFE workload API provider, issuing SVIDs to registered agents.
- Alternatively, agents **MAY** present SVIDs issued by an external SPIRE server; Hearth validates the SVID against the configured trust bundle.

### 11.3 mTLS Attestation

- Agents presenting X.509 SVIDs **MUST** authenticate via mTLS.
- Hearth's TLS termination layer (see [ARCHITECTURE.md Section 8](./ARCHITECTURE.md#8-security)) **MUST** extract the client certificate and map the SPIFFE ID to an `AgentId`.
- The mapping from SPIFFE ID to `AgentId` **MUST** be configured per realm.

### 11.4 Rules

- Workload identity is an **OPTIONAL** authentication method. Realms **MUST** explicitly enable it.
- Trust bundles **MUST** be configurable per realm (different realms may use different SPIRE domains).
- SVID validation **MUST** check: certificate chain, expiration, and SPIFFE ID format.
- Workload identity **SHOULD** be combinable with DPoP for defense-in-depth (mTLS for transport, DPoP for token binding).

---

## 12. Observability & Audit

### 12.1 Delegation-Aware Audit Events

Hearth's existing audit system (see [ARCHITECTURE.md Section 8.5](./ARCHITECTURE.md#85-audit-trail)) **MUST** be extended to capture agent delegation context.

**Every agent action audit event MUST include:**

| Field | Type | Description |
|-------|------|-------------|
| `actor` | String | The immediate actor (e.g., `agent:A`). |
| `on_behalf_of` | String (optional) | The delegating principal (e.g., `user:U`). |
| `delegation_chain` | Array of strings | Full chain: `["user:U", "agent:A", "agent:B"]`. |
| `tool` | String (optional) | The tool invoked, if applicable. |
| `approval_id` | String (optional) | The approval request that authorized this action, if applicable. |
| `token_jti` | String | The JTI of the token used for this action. |
| `dpop_jkt` | String (optional) | The DPoP key thumbprint, if token was sender-constrained. |

### 12.2 Agent-Specific Audit Actions

The audit action enum **MUST** be extended with:

| Action | Trigger |
|--------|---------|
| `AgentCreated` | Agent registered. |
| `AgentUpdated` | Agent metadata modified. |
| `AgentSuspended` | Agent suspended. |
| `AgentRevoked` | Agent permanently revoked. |
| `AgentDeleted` | Agent deleted (cascade). |
| `AgentDelegation` | Token issued via OBO or token exchange for an agent. |
| `AgentToolInvocation` | Agent invoked a tool (logged by resource server or Hearth proxy). |
| `ApprovalRequested` | Agent requested human approval. |
| `ApprovalGranted` | Human approved agent action. |
| `ApprovalDenied` | Human denied agent action. |
| `AgentTokenRevoked` | Agent token revoked (manual or CAEP-triggered). |
| `CrossRealmTrustCreated` | Cross-realm trust policy created. |
| `CrossRealmTrustRevoked` | Cross-realm trust policy revoked. |

### 12.3 Agent Rate Monitoring

- Hearth **SHOULD** maintain per-agent rate counters for: token requests, tool invocations, approval requests, and delegation events.
- Anomaly thresholds **SHOULD** be configurable per agent or per realm.
- When an agent exceeds its rate threshold, Hearth **SHOULD** emit a risk signal (see [Section 10.2](#102-risk-signals)) and **MAY** auto-suspend the agent.

### 12.4 Delegation Chain Visualization

- The admin UI **SHOULD** provide a delegation chain view: given a token or audit event, display the full chain of delegations that led to the action.
- The API **MUST** support querying audit events by agent ID, delegation chain membership, and tool invoked.

---

## 13. Storage Schema

### 13.1 Key Prefixes

All agent-related storage keys **MUST** be realm-prefixed per [ARCHITECTURE.md Section 7](./ARCHITECTURE.md#7-multi-tenancy).

| Prefix Pattern | Content |
|----------------|---------|
| `{realm}:agt:id:{agent_id}` | Agent entity record. |
| `{realm}:agt:owner:{owner_id}:{agent_id}` | Index: agents by owner. |
| `{realm}:agt:name:{name_hash}` | Index: agent by display name (for uniqueness within realm). |
| `{realm}:agt:cred:{agent_id}:{credential_id}` | Agent credential (API key hash, public key). |
| `{realm}:agt:card:{agent_id}` | Agent Card JSON. |
| `{realm}:tool:id:{tool_name}` | Tool registration record. |
| `{realm}:toolgrp:{group_name}:{tool_name}` | Tool group membership. |
| `{realm}:res:id:{resource_id}` | Protected resource (MCP server) record. |
| `{realm}:res:uri:{uri_hash}` | Index: protected resource by URI. |
| `{realm}:appreq:{request_id}` | Approval request record. |
| `{realm}:appreq:agt:{agent_id}:{request_id}` | Index: approval requests by agent. |
| `{realm}:appreq:pending:{request_id}` | Index: pending approval requests (for approver dashboard). |
| `{realm}:consent:{user_id}:{agent_id}` | User-to-agent consent record. |
| `{realm}:dpop:nonce:{nonce}` | DPoP server nonce (short-lived). |
| `{realm}:dpop:jti:{jti}` | DPoP proof replay prevention (short-lived). |
| `{realm}:xttrust:{source_realm}:{target_realm}` | Cross-realm trust policy. |

### 13.2 Storage Rules

- Agent records **MUST** use the same batch-write pattern as other identity operations per [ARCHITECTURE.md Section 6.1](./ARCHITECTURE.md#61-write-path-invariants): entity + indexes as a single WAL entry.
- DPoP nonce and JTI entries **MUST** use TTL-based expiry. The storage engine **SHOULD** support automatic expiry for these short-lived entries.
- Approval request status transitions **MUST** be atomic (compare-and-swap or conditional write).
- Cross-realm trust policies **MUST** be stored under both the source and target realm namespaces for bidirectional lookup.

---

## 14. Implementation Phases

Implementation **MUST** follow the dependency order below. Each phase builds on the previous.

### Phase A — Foundation (Agent Identity + DPoP)

| Step | Feature | Dependencies | Test Scenarios |
|------|---------|-------------|----------------|
| A.1 | `AgentId` newtype in `core/types.rs` | None | Unit: newtype construction, display, parsing. |
| A.2 | Agent entity, CRUD in identity engine | A.1 | Unit: create, read, update, delete, status transitions. Integration: cascade delete. Property: owner invariant. |
| A.3 | Agent credentials (API key, asymmetric key) | A.2 | Unit: key generation, hash storage, validation. Adversarial: timing attacks, brute force. |
| A.4 | Agent Card serving | A.2 | Integration: well-known endpoint, content negotiation. |
| A.5 | DPoP proof validation | None | Unit: proof parsing, signature verification, nonce, replay. Conformance: RFC 9449 test vectors. |
| A.6 | DPoP-bound token issuance | A.5 | Integration: full DPoP flow. Adversarial: token replay without proof, proof reuse. |
| A.7 | Agent protocol endpoints (REST) | A.2, A.3 | Integration: CRUD via HTTP, auth requirements. |

### Phase B — MCP & Delegation

| Step | Feature | Dependencies | Test Scenarios |
|------|---------|-------------|----------------|
| B.1 | Protected resource registration | A.2 | Unit: CRUD, URI uniqueness. Integration: registration flow. |
| B.2 | Resource Indicators (RFC 8707) | B.1 | Unit: `resource` parameter parsing, `aud` claim. Conformance: RFC 8707 semantics. |
| B.3 | Protected Resource Metadata | B.1 | Integration: well-known endpoint, content. |
| B.4 | Token Exchange (RFC 8693) | A.6 | Unit: grant type, scope intersection, `act` claim. Integration: full exchange flow. |
| B.5 | On-Behalf-Of extension | B.4 | Unit: `requested_actor`, `actor_token`. Integration: OBO flow with consent. |
| B.6 | Consent management | B.5 | Unit: consent CRUD, scope storage. Integration: consent + revocation. |
| B.7 | Delegation chain enforcement | B.5 | Unit: depth limit, scope attenuation. Property: scope only narrows. Adversarial: escalation attempts. |

### Phase C — Permissions & Approval

| Step | Feature | Dependencies | Test Scenarios |
|------|---------|-------------|----------------|
| C.1 | Tool permission conventions + tool registry | A.2 | Unit: `tool.*`/`toolgroup.*` permission grammar; tool-registry config loading. |
| C.2 | `invoke` / `invoke_with_approval` / `deny` evaluation | C.1 | Unit: precedence rules (deny wins). Integration: claim inspection yields correct decision. Property: deny always wins. |
| C.3 | Scope intersection at delegation | B.4, C.1 | Unit: intersection logic. Property: result is always subset. |
| C.4 | Approval request lifecycle | C.2 | Unit: create, approve, deny, expire. Integration: full flow. |
| C.5 | Approval webhook notifications | C.4 | Integration: webhook delivery. |
| C.6 | Approval in admin UI | C.4 | Integration: list, approve, deny via UI. |

### Phase D — Advanced (AATs, A2A, CAEP)

| Step | Feature | Dependencies | Test Scenarios |
|------|---------|-------------|----------------|
| D.1 | AAT issuance and validation | B.4 | Unit: derivation rules, chain validation. Property: scope only narrows. Adversarial: escalation via crafted AATs. |
| D.2 | Agent discovery and registry | A.4 | Integration: search by capability. |
| D.3 | Transaction tokens | A.6 | Unit: single-use, expiry. Adversarial: replay. |
| D.4 | Cross-realm trust policies | A.2 | Unit: policy CRUD. Integration: cross-realm token issuance. Adversarial: trust bypass. |
| D.5 | CAEP risk signals | A.2 | Unit: signal emission. Integration: signal → revocation. |
| D.6 | Agent rate monitoring | A.2 | Unit: counter increment, threshold detection. Integration: auto-suspend on anomaly. |
| D.7 | Workload identity (SPIFFE) | A.3 | Integration: mTLS + SVID → AgentId mapping. |
| D.8 | Delegation chain audit + visualization | B.7, C.4 | Integration: audit query by chain. UI: chain rendering. |

---

## 15. Standards Reference

| Standard | Identifier | Status | Hearth Feature |
|----------|-----------|--------|----------------|
| OAuth 2.1 | draft-ietf-oauth-v2-1 | Draft (near-final) | Baseline authorization server |
| DPoP | RFC 9449 | Published | Proof-of-possession ([Section 6](#6-proof-of-possession-dpop)) |
| Token Exchange | RFC 8693 | Published | Delegated authorization ([Section 3.3](#33-token-exchange-rfc-8693)) |
| Resource Indicators | RFC 8707 | Published | MCP token scoping ([Section 2.3](#23-resource-indicators-rfc-8707)) |
| Protected Resource Metadata | RFC 9728 | Published | MCP server discovery ([Section 2.4](#24-protected-resource-metadata-rfc-9728)) |
| Dynamic Client Registration | RFC 7591 | Published | Agent auto-registration ([Section 2.7](#27-dynamic-client-registration)) |
| On-Behalf-Of for Agents | draft-oauth-ai-agents-on-behalf-of-user-02 | Draft | OBO delegation ([Section 3.2](#32-on-behalf-of-extension-obo)) |
| Attenuating Agent Tokens | draft-niyikiza-oauth-attenuating-agent-tokens | Draft | Scope attenuation ([Section 4](#4-scope-attenuation)) |
| Transaction Tokens for Agents | draft-oauth-transaction-tokens-for-agents | Draft | A2A transactions ([Section 8.5](#85-transaction-tokens)) |
| Agent Identity Protocol | draft-prakash-aip | Draft | Agent identity model ([Section 1](#1-agent-identity)) |
| A2A Protocol | Google A2A v0.3 | Industry | Agent Cards, discovery ([Section 1.6](#16-agent-cards-a2a-protocol), [Section 8](#8-agent-to-agent-trust)) |
| MCP Authorization | MCP Spec 2026-03-26 | Stable | MCP authorization server ([Section 2](#2-mcp-authorization-server)) |
| SPIFFE | SPIFFE v1.0 | Published | Workload identity ([Section 11](#11-workload-identity)) |
| CAEP | OpenID SSF/CAEP | Draft | Continuous access evaluation ([Section 10](#10-continuous-access-evaluation)) |

---

## Appendix: Decision Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Agent as distinct entity | Not an OAuth client | Agents need delegation chains, capability declarations, and per-agent policy that OAuth clients don't model. Collapsing them loses audit context and prevents proper lifecycle management. |
| Tool permissions via RBAC claims | Not scope strings alone | RBAC permissions are queryable, auditable, and embedded in JWT claims. Scope strings are flat OAuth-level labels; permissions are the authoritative source. Tools map naturally to permission strings (`tool.{name}.invoke`), agents to principals. Layering scope on top of permissions lets OAuth clients downscope at token exchange time. |
| DPoP over mTLS (default) | Ed25519 DPoP proofs | Aligns with Hearth's Ed25519 signing. DPoP works through proxies and load balancers where mTLS terminates. mTLS remains an option for infrastructure contexts. |
| `act` claim for delegation | Per RFC 8693 Section 4.1 | Industry standard. Nested `act` claims naturally express chains of arbitrary depth without schema changes. |
| AAT offline derivation | Not server-mediated attenuation | Each hop can narrow scope without round-tripping to Hearth. Critical for latency in multi-agent chains. Aligns with draft-niyikiza-oauth-attenuating-agent-tokens. |
| Human-in-the-loop via RBAC permission | `tool.{name}.invoke_with_approval` | Reuses existing permission infrastructure. No separate policy engine. Approval requirement is just another permission string, auditable and revocable like any other grant. |
| CAEP via audit stream | Not a separate event bus | Risk signals ride on Hearth's existing audit event stream. A dedicated push channel would duplicate the audit-materialization path. When a risk signal fires, subscribers consume it from the audit stream and act (revoke session, suspend agent, etc.). |
| MCP servers as protected resources | Registered in Hearth config | Tokens need audience restriction. Registering MCP servers gives Hearth the URI vocabulary for `aud` claims and enables PRM discovery. |
| Phased implementation | A → B → C → D | Each phase has clear dependencies. Foundation (identity + DPoP) must exist before delegation. Delegation must exist before tool permissions. Advanced features (AATs, CAEP) build on all prior phases. |
| Agent Cards at well-known path | Per A2A protocol | Interoperability with the emerging A2A ecosystem. Minimal cost (JSON endpoint), high value (agent discovery). |
| Cross-realm trust explicit-only | No implicit trust | Security default. Cross-realm agent interactions are high-risk (data boundary crossing). Explicit configuration forces deliberate trust decisions. |
| Transaction tokens single-use | 60-second max lifetime | Agent-to-agent calls should be transactional. Longer-lived tokens for A2A invite replay attacks. Single-use + short TTL minimizes exposure. |
| Scope intersection (not union) | At delegation time | Least privilege. The effective scope can never exceed any single input. Fail-fast at issuance prevents confusing denials at resource access time. |
