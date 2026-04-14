# Hearth Test Scenario Checklist

A granular, checkbox-tracked list of every test scenario needed for Hearth, organized by module and testing layer. Complements [TESTING.md](./TESTING.md) (strategy, tooling, CI tiers) and [VISION.md](../vision/VISION.md) (architecture, performance targets, Phase 0 scope).

**Format**: `- [ ] Scenario description \`priority\` \`ci-tier\``
- **Priority**: `P0` (blocks phase exit) / `P1` (important) / `P2` (nice-to-have)
- **CI tier**: `fast` (<5 min) / `standard` (<15 min) / `extended` (<60 min) / `full` (<4 hrs)
- **Testing layer**: implicit from subsection heading
- **Phase**: implicit from document section

---

## Progress Matrix

Phase 0 scenario counts by module and testing layer. `0/N` = completed/total. `--` = not applicable.

| Module | Unit | Integration | Property | Fuzz | Simulation | Adversarial | Conformance | Benchmark | **Total** |
|--------|------|-------------|----------|------|------------|-------------|-------------|-----------|-----------|
| Test Infrastructure | 0/2 | 0/2 | -- | -- | -- | -- | -- | -- | **0/4** |
| Storage: WAL | 5/5 | -- | 3/3 | 0/1 | 0/3 | -- | -- | -- | **8/12** |
| Storage: Memtable | 5/5 | -- | 2/2 | -- | -- | -- | -- | -- | **7/7** |
| Storage: Persistence | 0/4 | -- | 0/2 | -- | 0/3 | -- | -- | -- | **0/9** |
| Storage: Tiered Hot/Cold | 0/5 | -- | 0/2 | -- | 0/2 | -- | -- | 0/3 | **0/12** |
| User CRUD | 0/5 | 0/3 | 0/2 | -- | -- | 0/2 | -- | 0/2 | **0/14** |
| Credential Storage | 0/4 | 0/2 | 0/2 | 0/1 | -- | 0/3 | -- | -- | **0/12** |
| Session Management | 0/5 | 0/3 | 0/2 | -- | 0/2 | 0/3 | -- | 0/2 | **0/17** |
| Authorization Engine | 0/5 | 0/2 | 0/3 | -- | -- | 0/3 | -- | 0/2 | **0/15** |
| JWT / Tokens | 0/5 | 0/2 | -- | 0/1 | -- | 0/4 | -- | 0/2 | **0/14** |
| OIDC (Auth Code Flow) | 0/5 | 0/3 | -- | 0/1 | -- | 0/3 | 0/2 | 0/1 | **0/15** |
| Configuration | 0/4 | -- | -- | 0/1 | -- | -- | -- | -- | **0/5** |
| CLI Tool | -- | 0/3 | -- | -- | -- | -- | -- | -- | **0/3** |
| End-to-End Flows | -- | 0/4 | -- | -- | -- | -- | -- | -- | **0/4** |
| Cross-Cutting Concerns | -- | -- | -- | -- | -- | 0/5 | -- | -- | **0/5** |
| **Column Total** | **10/54** | **0/24** | **5/18** | **0/5** | **0/10** | **0/23** | **0/2** | **0/12** | **15/148** |

---

## Phase 0: Foundation

### Test Infrastructure

#### Unit

- [ ] TestHarness embedded mode starts with isolated temp directory and stops cleanly `P0` `fast`
- [ ] TestHarness server mode starts on random port, accepts connections, and stops cleanly `P0` `fast`

#### Integration

- [ ] Dual-mode test pattern: same async test logic runs against both embedded and server modes `P0` `fast`
- [ ] Server-mode tests are `#[ignore]`-tagged until HTTP layer exists `P1` `fast`

---

### Storage: WAL

#### Unit

- [x] Append single entry and read back matches original `P0` `fast`
- [x] Append multiple entries and read back preserves insertion order `P0` `fast`
- [x] WAL fsync on commit guarantees durability (entry persists after process restart) `P0` `fast`
- [x] Empty WAL returns no entries on read `P0` `fast`
- [x] WAL file rotation triggers at configured size threshold `P1` `fast`

#### Property

- [x] Random write sequences maintain append-order integrity (`proptest`, 256/10K+ cases) `P0` `extended`
- [x] WAL replay after any prefix of operations produces consistent state `P0` `extended`
- [x] Entry serialization round-trip: `deserialize(serialize(entry)) == entry` for arbitrary entries `P0` `extended`

#### Simulation

- [ ] Crash mid-write: WAL recovers to last fully committed entry (`madsim` fault injection) `P0` `full`
- [ ] Crash mid-fsync: recovery produces valid state without corruption `P0` `full`
- [ ] Simulated disk I/O failure during append returns error with no partial writes `P0` `full`

#### Fuzz

- [ ] Arbitrary bytes to WAL entry deserialization never panic (`cargo-fuzz`) `P1` `extended`

---

### Storage: Memtable

#### Unit

- [x] Insert and retrieve key-value pairs (single and multiple) `P0` `fast`
- [x] Update existing key overwrites value; subsequent read returns new value `P0` `fast`
- [x] Delete key removes entry; subsequent lookup returns `None` `P0` `fast`
- [x] Flush threshold triggers when memtable reaches configured byte size `P0` `fast`
- [x] Iterator returns entries in sorted key order `P0` `fast`

#### Property

- [x] Random insert/update/delete sequences maintain correct key set (`proptest`) `P0` `extended`
- [x] Concurrent reads during writes see consistent snapshots (lock-free read validation) `P0` `extended`

---

### Storage: Persistence

#### Unit

- [ ] Flush memtable to SST file produces valid on-disk format `P0` `fast`
- [ ] Read data back from SST after flush matches original memtable contents `P0` `fast`
- [ ] Compaction merges multiple SST files correctly (dedup, tombstone removal) `P0` `fast`
- [ ] Point lookup and range scan over SST return correct results `P1` `fast`

#### Property

- [ ] Random write → flush → read cycles maintain full data integrity (`proptest`) `P0` `extended`
- [ ] Compaction preserves all live keys and correctly removes tombstoned entries `P0` `extended`

#### Simulation

- [ ] Crash during memtable flush: recovery loses no committed data (`madsim`) `P0` `full`
- [ ] Crash during compaction: recovery produces valid SST state `P0` `full`
- [ ] Power-loss simulation: all fsync'd data survives across crash-recovery cycles `P0` `full`

---

### Storage: Tiered Hot/Cold

#### Unit

- [ ] Recently accessed records remain in hot tier across subsequent reads `P0` `fast`
- [ ] Records not accessed within eviction window are demoted to cold tier `P0` `fast`
- [ ] Cold-tier read promotes record back to hot tier; subsequent reads hit hot tier `P0` `fast`
- [ ] Clock-based LRU approximation evicts least-recently-used records correctly `P0` `fast`
- [ ] Hot tier auto-sizes based on available system memory / cgroup memory limit `P1` `fast`

#### Property

- [ ] Random access patterns produce correct eviction and promotion behavior (`proptest`) `P0` `extended`
- [ ] Power-law access distribution: hot tier converges to active working set `P0` `extended`

#### Simulation

- [ ] Tier transitions preserve all data under concurrent read/write load (`madsim`) `P0` `full`
- [ ] Crash during promotion or eviction: recovery produces consistent tier state `P0` `full`

#### Benchmark

- [ ] Hot-tier session lookup: p50 < 10 μs, p99 < 100 μs (regression threshold: +20%) `P0` `standard`
- [ ] Cold-to-hot promotion latency: < 5 ms on NVMe storage `P1` `standard`
- [ ] Memory footprint: < 500 MB for 1M hot users `P1` `standard`

---

### User CRUD

#### Unit

- [ ] Create user with required fields succeeds and returns assigned ID `P0` `fast`
- [ ] Read user by ID and by email both return correct record `P0` `fast`
- [ ] Update user fields persists changes; subsequent read reflects updates `P0` `fast`
- [ ] Delete user removes record; subsequent read returns not-found `P0` `fast`
- [ ] Duplicate email on create rejected with appropriate error `P0` `fast`

#### Integration

- [ ] Full CRUD lifecycle via embedded public API (zero internal imports) `P0` `fast`
- [ ] Full CRUD lifecycle via server HTTP API `P1` `fast`
- [ ] Delete user cascades: associated sessions invalidated, credentials removed `P0` `fast`

#### Property

- [ ] Random create/read/update/delete sequences maintain consistent user count (`proptest`) `P0` `extended`
- [ ] Email uniqueness constraint holds under random concurrent creation sequences `P0` `extended`

#### Adversarial

- [ ] Null bytes in usernames and unicode normalization attacks handled safely `P0` `fast`
- [ ] Oversized input fields (username, email, metadata) rejected gracefully `P0` `fast`

#### Benchmark

- [ ] User lookup by email/ID: p50 < 50 μs, p99 < 500 μs (regression: +20%) `P0` `standard`
- [ ] User creation with Argon2id hashing: p50 < 50 ms, p99 < 100 ms `P0` `standard`

---

### Credential Storage

#### Unit

- [ ] Store and verify Argon2id-hashed password: correct password succeeds, wrong password fails `P0` `fast`
- [ ] Multi-algorithm verification: bcrypt/scrypt credentials from migration verify correctly `P0` `fast`
- [ ] Password change updates stored credential; old password no longer verifies `P0` `fast`
- [ ] Key derivation parameters (memory cost, time cost, parallelism) are configurable `P1` `fast`

#### Integration

- [ ] Credential storage, verification, and change via public API `P0` `fast`
- [ ] Password change flow end-to-end (authenticate → change → re-authenticate) `P0` `fast`

#### Property

- [ ] Arbitrary byte inputs to credential parsing functions never panic (`proptest`) `P0` `extended`
- [ ] Stored credential is always verifiable with the original password (round-trip) `P0` `extended`

#### Fuzz

- [ ] Arbitrary bytes to password hash verification never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [ ] Constant-time password comparison: statistical timing analysis shows no measurable difference between valid/invalid users `P0` `fast`
- [ ] Password hashes never appear in API responses, error messages, or log output `P0` `fast`
- [ ] Rate limiting engages under sustained credential guessing attempts `P1` `fast`

---

### Session Management

#### Unit

- [ ] Create session returns valid session ID bound to correct user `P0` `fast`
- [ ] Lookup session by ID returns correct session data and user association `P0` `fast`
- [ ] Revoke session: immediate invalidation, subsequent lookup fails `P0` `fast`
- [ ] TTL expiration: session becomes invalid after configured timeout `P0` `fast`
- [ ] Refresh session extends TTL; session remains valid past original expiry `P0` `fast`

#### Integration

- [ ] Full lifecycle (create → validate → refresh → revoke → validate-fails) via embedded API `P0` `fast`
- [ ] Full lifecycle via server HTTP API `P1` `fast`
- [ ] Session data persists across server restart (WAL durability) `P0` `fast`

#### Property

- [ ] Random create/revoke sequences maintain consistent active session count (`proptest`) `P0` `extended`
- [ ] No session ID collisions across 10,000+ random generations `P0` `extended`

#### Simulation

- [ ] Crash recovery: no committed session is lost (`madsim` oracle assertion) `P0` `full`
- [ ] TTL expiration correct under simulated clock skew / time drift `P1` `full`

#### Adversarial

- [ ] Replayed session tokens rejected after revocation `P0` `fast`
- [ ] Session fixation: pre-authentication session ID cannot be reused post-authentication `P0` `fast`
- [ ] Enumeration resistance: responses for invalid, expired, and nonexistent session IDs are indistinguishable `P0` `fast`

#### Benchmark

- [ ] Session lookup by ID: p50 < 10 μs, p99 < 100 μs (regression: +20%) `P0` `standard`
- [ ] Session creation throughput: > 50,000 ops/sec/core `P1` `standard`

---

### Authorization Engine

#### Unit

- [ ] Direct relationship check: returns true when present, false when absent `P0` `fast`
- [ ] Transitive relationship check: correctly resolves 2-hop and 3-hop paths `P0` `fast`
- [ ] Cycle detection: relationship graph rejects or handles cycles correctly `P0` `fast`
- [ ] Write and delete relationship tuples; check reflects changes immediately `P0` `fast`
- [ ] Expand operation returns complete set of reachable subjects `P0` `fast`

#### Integration

- [ ] Permission check via embedded public API (zero internal imports) `P0` `fast`
- [ ] Write relationship + check permission round-trip via public API `P0` `fast`

#### Property

- [ ] Random relationship graphs produce correct reachability results (`proptest`) `P0` `extended`
- [ ] Cycle detection holds for arbitrary graph topologies `P0` `extended`
- [ ] Random add/delete sequences maintain graph invariants (acyclicity, referential integrity) `P0` `extended`

#### Adversarial

- [ ] Malformed permission tuples (invalid object/relation/subject) rejected safely `P0` `fast`
- [ ] Cross-tenant permission leak prevented: namespace traversal returns no results `P0` `fast`
- [ ] Maximum graph traversal depth enforced to prevent DoS via deep chains `P0` `fast`

#### Benchmark

- [ ] Direct permission check: p50 < 20 μs, p99 < 200 μs (regression: +20%) `P0` `standard`
- [ ] 3-hop graph traversal: p50 < 100 μs, p99 < 1 ms (regression: +20%) `P0` `standard`

---

### JWT / Tokens

#### Unit

- [ ] Issue JWT with correct standard claims (`sub`, `iss`, `aud`, `exp`, `iat`) `P0` `fast`
- [ ] Validate JWT: correct signature returns success with parsed claims `P0` `fast`
- [ ] Reject expired, tampered-payload, and wrong-signing-key JWTs `P0` `fast`
- [ ] Token refresh issues new JWT with extended expiration `P0` `fast`
- [ ] JWKS endpoint returns correct public keys in standard format `P0` `fast`

#### Integration

- [ ] Token issuance and validation round-trip via public API `P0` `fast`
- [ ] Token refresh flow end-to-end (issue → expire → refresh → validate) `P0` `fast`

#### Fuzz

- [ ] Arbitrary bytes to JWT parsing (header, payload, signature) never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [ ] `alg=none` attack: unsigned token rejected regardless of claims `P0` `fast`
- [ ] RSA/HMAC key confusion: HMAC-signed token with RSA public key as secret rejected `P0` `fast`
- [ ] Modified `exp`, `iss`, or `aud` claims detected and rejected on validation `P0` `fast`
- [ ] Nonce reuse in token requests detected (when nonce enforcement enabled) `P1` `fast`

#### Benchmark

- [ ] Token validation (JWT verify + session lookup): p50 < 50 μs, p99 < 500 μs (regression: +20%) `P0` `standard`
- [ ] Token issuance (full OAuth2 flow): p50 < 1 ms, p99 < 5 ms (regression: +20%) `P0` `standard`

---

### OIDC (Authorization Code Flow)

#### Unit

- [ ] Generate authorization code with correct parameters (client_id, redirect_uri, scope, state) `P0` `fast`
- [ ] Exchange valid authorization code for access + ID tokens `P0` `fast`
- [ ] Authorization code single-use: second exchange attempt rejected `P0` `fast`
- [ ] Authorization code expiration: exchange after timeout rejected `P0` `fast`
- [ ] Discovery document at `.well-known/openid-configuration` returns correct metadata `P0` `fast`

#### Integration

- [ ] Full authorization code flow via embedded API (authorize → exchange → validate) `P0` `fast`
- [ ] Full authorization code flow via HTTP endpoints `P1` `fast`
- [ ] PKCE (S256): code challenge generated, code verifier validated on exchange `P0` `fast`

#### Fuzz

- [ ] Arbitrary bytes to OIDC authorization/token request parsers never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [ ] Authorization code reuse and injection attacks rejected `P0` `fast`
- [ ] Open redirect via `redirect_uri` manipulation: non-registered URIs rejected `P0` `fast`
- [ ] CSRF prevention: missing or invalid `state` parameter causes flow rejection `P0` `fast`

#### Conformance

- [ ] Discovery endpoint conforms to OpenID Connect Discovery 1.0 specification `P1` `full`
- [ ] Token endpoint behavior conforms to OAuth 2.0 (RFC 6749) token exchange spec `P1` `full`

#### Benchmark

- [ ] Authorization code exchange latency: p50 < 1 ms, p99 < 5 ms (regression: +20%) `P1` `standard`

---

### Configuration

#### Unit

- [ ] Parse valid TOML/YAML server configuration file `P0` `fast`
- [ ] Reject invalid configuration with descriptive, actionable error messages `P0` `fast`
- [ ] Default values applied correctly for all omitted optional fields `P0` `fast`
- [ ] `--dev` flag applies development-mode defaults (in-memory, relaxed security, test users) `P0` `fast`

#### Fuzz

- [ ] Arbitrary bytes to configuration parser never panic (`cargo-fuzz`) `P0` `extended`

---

### CLI Tool

#### Integration

- [ ] `hearth serve --dev` starts server and accepts connections `P0` `fast`
- [ ] CLI management commands (`tenant create`, `app create`) succeed against running server `P1` `fast`
- [ ] CLI exits with appropriate non-zero error codes on invalid input or unreachable server `P0` `fast`

---

### End-to-End Flows

#### Integration

- [ ] Developer on-ramp: start server → create tenant → create app → complete OIDC login `P0` `fast`
- [ ] User lifecycle: register → authenticate → receive session → validate token `P0` `fast`
- [ ] Auth + authz: authenticate → write permission → check permission → authorized action succeeds `P0` `fast`
- [ ] Cascading invalidation: delete user → sessions invalidated → token validation fails `P0` `fast`

---

### Cross-Cutting Concerns

#### Adversarial

- [ ] All API error responses leak no internal state (no stack traces, internal paths, or query details) `P0` `fast`
- [ ] Constant-time comparisons used for all secret-derived values (tokens, session IDs, auth codes) `P0` `fast`
- [ ] No credential material, tokens, or session IDs appear in log output at any log level `P0` `fast`
- [ ] Sensitive data (passwords, keys, tokens) zeroed from memory after use `P0` `fast`
- [ ] Input size limits enforced across all API endpoints (request body, header, URL length) `P0` `fast`

---

## Phases 1–3+

High-level test categories for future phases. Individual checkboxes will be expanded as each phase begins development.

### Phase 1: Production Single-Node

- **OAuth 2.0 complete** — client credentials, device authorization, refresh token rotation (Integration, Property, Adversarial, Benchmark)
- **WebAuthn / Passkeys** — registration, authentication, attestation validation (Integration, Fuzz, Adversarial)
- **Magic link / passwordless** — email-based authentication flow (Integration, Adversarial)
- **TOTP / MFA** — setup, validation, recovery codes (Unit, Integration, Adversarial)
- **Multi-tenancy** — tenant isolation, per-tenant configuration, cross-tenant prevention (Unit, Integration, Property, Adversarial)
- **Zanzibar authorization** — full Check/Expand/Write/Watch API (Unit, Integration, Property, Simulation, Adversarial, Benchmark)
- **Admin API** — REST + gRPC management endpoints (Integration, Adversarial)
- **Audit logging** — append-only mutation log, compliance queries (Unit, Integration, Property)
- **TLS termination** — certificate handling, protocol negotiation (Integration, Adversarial)
- **TypeScript and Go SDKs** — client library correctness against all supported flows (Integration)
- **OIDC conformance** — OpenID Connect certification test suite (Conformance)

### Phase 2: Production Clustering

- **Raft consensus** — leader election, log replication, snapshot recovery (Unit, Simulation, Benchmark)
- **Network partition handling** — split-brain prevention, quorum enforcement (Simulation)
- **SAML 2.0** — SP and IdP flows, XML signature validation (Integration, Fuzz, Conformance)
- **SCIM 2.0** — user provisioning, bulk operations (Integration, Conformance)
- **Migration tools** — Auth0 and Clerk import (Integration)
- **Multi-node integration** — replication consistency, cross-node permission checks, failover (Integration, Simulation, Benchmark)

### Phase 3+: Scale and Ecosystem

- **Multi-region replication** — configurable consistency, latency-optimized routing (Simulation, Benchmark)
- **Hearth Cloud** — managed offering, tenant provisioning, billing integration (Integration)
- **S3 cold storage** — audit log archival, cold-tier offload to object storage (Integration, Simulation)
- **Remaining SDKs** — Python, Rust, Java, C#, Ruby, Elixir (Integration)

---

## Benchmark Targets Reference

All benchmark thresholds from VISION.md §7.1. Regression threshold for all operations: **+20%**.

| Operation | p50 | p99 | Cold Path | Throughput Target |
|-----------|-----|-----|-----------|-------------------|
| Token validation (JWT verify + session lookup) | < 50 μs | < 500 μs | < 5 ms | 200K+ ops/sec/core |
| Session lookup by ID | < 10 μs | < 100 μs | N/A (always hot) | — |
| Permission check (direct) | < 20 μs | < 200 μs | < 5 ms | 150K+ ops/sec/core |
| Permission check (3-hop traversal) | < 100 μs | < 1 ms | < 10 ms | — |
| User lookup by email/ID | < 50 μs | < 500 μs | < 5 ms | — |
| Token issuance (full OAuth2 flow) | < 1 ms | < 5 ms | < 10 ms | — |
| User creation (Argon2id) | < 50 ms | < 100 ms | N/A (write) | 50K+ ops/sec/core |
| Session creation | — | — | N/A (write) | 50K+ ops/sec/core |
| Cold-to-hot promotion | — | — | < 5 ms (NVMe) | — |

**Capacity targets** (single node):

| Metric | Target |
|--------|--------|
| Total managed users | 100M+ |
| Active sessions | 10M+ |
| Relationship tuples | 1B+ |
| Memory (1M hot users) | < 500 MB |
| Memory (10M hot users) | < 8 GB |
| Binary size | < 50 MB |
| Cold start to serving | < 2 seconds |

---

## Adversarial Test Categories Reference

All categories from TESTING.md §6, mapped to Phase 0 modules where applicable.

| Category | Phase 0 Coverage |
|----------|-----------------|
| Timing attacks | Credential Storage, Cross-Cutting Concerns |
| Token forgery | JWT / Tokens (`alg=none`, key confusion, claim tampering) |
| Privilege escalation | Authorization Engine (malformed tuples, namespace traversal, depth limits) |
| Replay attacks | Session Management (replayed tokens), OIDC (code reuse) |
| Input injection | User CRUD (null bytes, unicode), Cross-Cutting (size limits) |
| Credential stuffing | Credential Storage (rate limiting) |
