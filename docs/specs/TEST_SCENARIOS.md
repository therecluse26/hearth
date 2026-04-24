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
| Test Infrastructure | 2/2 | 2/2 | -- | -- | -- | -- | -- | -- | **4/4** |
| Storage: WAL | 5/5 | -- | 3/3 | 1/1 | 3/3 | -- | -- | -- | **12/12** |
| Storage: Memtable | 5/5 | -- | 2/2 | -- | -- | -- | -- | -- | **7/7** |
| Storage: Persistence | 4/4 | -- | 2/2 | -- | 3/3 | -- | -- | -- | **9/9** |
| Storage: Tiered Hot/Cold | 5/5 | -- | 2/2 | -- | 2/2 | -- | -- | 3/3 | **12/12** |
| User CRUD | 5/5 | 3/3 | 2/2 | -- | -- | 2/2 | -- | 2/2 | **14/14** |
| Credential Storage | 4/4 | 2/2 | 2/2 | 1/1 | -- | 3/3 | -- | -- | **12/12** |
| Session Management | 5/5 | 3/3 | 2/2 | -- | 2/2 | 3/3 | -- | 2/2 | **17/17** |
| Authorization Engine | 5/5 | 2/2 | 3/3 | -- | -- | 3/3 | -- | 2/2 | **15/15** |
| JWT / Tokens | 5/5 | 2/2 | -- | 1/1 | -- | 4/4 | -- | 2/2 | **14/14** |
| OIDC (Auth Code Flow) | 5/5 | 3/3 | -- | 1/1 | -- | 3/3 | 2/2 | 1/1 | **15/15** |
| Configuration | 4/4 | -- | -- | 1/1 | -- | -- | -- | -- | **5/5** |
| CLI Tool | -- | 3/3 | -- | -- | -- | -- | -- | -- | **3/3** |
| End-to-End Flows | -- | 4/4 | -- | -- | -- | -- | -- | -- | **4/4** |
| Cross-Cutting Concerns | -- | -- | -- | -- | -- | 5/5 | -- | -- | **5/5** |
| **Column Total** | **54/54** | **24/24** | **18/18** | **5/5** | **10/10** | **23/23** | **2/2** | **12/12** | **148/148** |

---

## Phase 0: Foundation

### Test Infrastructure

#### Unit

- [x] TestHarness embedded mode starts with isolated temp directory and stops cleanly `P0` `fast`
- [x] TestHarness server mode starts on random port, accepts connections, and stops cleanly `P0` `fast`

#### Integration

- [x] Dual-mode test pattern: same async test logic runs against both embedded and server modes `P0` `fast`
- [x] Server-mode tests are `#[ignore]`-tagged until HTTP layer exists `P1` `fast`

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

- [x] Crash mid-write: WAL recovers to last fully committed entry (`madsim` fault injection) `P0` `full`
- [x] Crash mid-fsync: recovery produces valid state without corruption `P0` `full`
- [x] Simulated disk I/O failure during append returns error with no partial writes `P0` `full`

#### Fuzz

- [x] Arbitrary bytes to WAL entry deserialization never panic (`cargo-fuzz`) `P1` `extended`

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

- [x] Flush memtable to SST file produces valid on-disk format `P0` `fast`
- [x] Read data back from SST after flush matches original memtable contents `P0` `fast`
- [x] Compaction merges multiple SST files correctly (dedup, tombstone removal) `P0` `fast`
- [x] Point lookup and range scan over SST return correct results `P1` `fast`

#### Property

- [x] Random write → flush → read cycles maintain full data integrity (`proptest`) `P0` `extended`
- [x] Compaction preserves all live keys and correctly removes tombstoned entries `P0` `extended`

#### Simulation

- [x] Crash during memtable flush: recovery loses no committed data (`madsim`) `P0` `full`
- [x] Crash during compaction: recovery produces valid SST state `P0` `full`
- [x] Power-loss simulation: all fsync'd data survives across crash-recovery cycles `P0` `full`

---

### Storage: Tiered Hot/Cold

#### Unit

- [x] Recently accessed records remain in hot tier across subsequent reads `P0` `fast`
- [x] Records not accessed within eviction window are demoted to cold tier `P0` `fast`
- [x] Cold-tier read promotes record back to hot tier; subsequent reads hit hot tier `P0` `fast`
- [x] Clock-based LRU approximation evicts least-recently-used records correctly `P0` `fast`
- [x] Hot tier auto-sizes based on available system memory / cgroup memory limit `P1` `fast`

#### Property

- [x] Random access patterns produce correct eviction and promotion behavior (`proptest`) `P0` `extended`
- [x] Power-law access distribution: hot tier converges to active working set `P0` `extended`

#### Simulation

- [x] Tier transitions preserve all data under concurrent read/write load (`madsim`) `P0` `full`
- [x] Crash during promotion or eviction: recovery produces consistent tier state `P0` `full`

#### Benchmark

- [x] Hot-tier session lookup: p50 < 10 μs, p99 < 100 μs (regression threshold: +20%) `P0` `standard`
- [x] Cold-to-hot promotion latency: < 5 ms on NVMe storage `P1` `standard`
- [x] Memory footprint: < 500 MB for 1M hot users `P1` `standard`

---

### User CRUD

#### Unit

- [x] Create user with required fields succeeds and returns assigned ID `P0` `fast`
- [x] Read user by ID and by email both return correct record `P0` `fast`
- [x] Update user fields persists changes; subsequent read reflects updates `P0` `fast`
- [x] Delete user removes record; subsequent read returns not-found `P0` `fast`
- [x] Duplicate email on create rejected with appropriate error `P0` `fast`

#### Integration

- [x] Full CRUD lifecycle via embedded public API (zero internal imports) `P0` `fast`
- [x] Full CRUD lifecycle via server HTTP API `P1` `fast`
- [x] Delete user cascades: associated sessions invalidated, credentials removed `P0` `fast`

#### Property

- [x] Random create/read/update/delete sequences maintain consistent user count (`proptest`) `P0` `extended`
- [x] Email uniqueness constraint holds under random concurrent creation sequences `P0` `extended`

#### Adversarial

- [x] Null bytes in usernames and unicode normalization attacks handled safely `P0` `fast`
- [x] Oversized input fields (username, email, metadata) rejected gracefully `P0` `fast`

#### Benchmark

- [x] User lookup by email/ID: p50 < 50 μs, p99 < 500 μs (regression: +20%) `P0` `standard`
- [x] User creation with Argon2id hashing: p50 < 50 ms, p99 < 100 ms `P0` `standard`

---

### Credential Storage

#### Unit

- [x] Store and verify Argon2id-hashed password: correct password succeeds, wrong password fails `P0` `fast`
- [x] Multi-algorithm verification: bcrypt/scrypt credentials from migration verify correctly `P0` `fast`
- [x] Password change updates stored credential; old password no longer verifies `P0` `fast`
- [x] Key derivation parameters (memory cost, time cost, parallelism) are configurable `P1` `fast`

#### Integration

- [x] Credential storage, verification, and change via public API `P0` `fast`
- [x] Password change flow end-to-end (authenticate → change → re-authenticate) `P0` `fast`

#### Property

- [x] Arbitrary byte inputs to credential parsing functions never panic (`proptest`) `P0` `extended`
- [x] Stored credential is always verifiable with the original password (round-trip) `P0` `extended`

#### Fuzz

- [x] Arbitrary bytes to password hash verification never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [x] Constant-time password comparison: statistical timing analysis shows no measurable difference between valid/invalid users `P0` `fast`
- [x] Password hashes never appear in API responses, error messages, or log output `P0` `fast`
- [x] Rate limiting engages under sustained credential guessing attempts `P1` `fast`

---

### Session Management

#### Unit

- [x] Create session returns valid session ID bound to correct user `P0` `fast`
- [x] Lookup session by ID returns correct session data and user association `P0` `fast`
- [x] Revoke session: immediate invalidation, subsequent lookup fails `P0` `fast`
- [x] TTL expiration: session becomes invalid after configured timeout `P0` `fast`
- [x] Refresh session extends TTL; session remains valid past original expiry `P0` `fast`

#### Integration

- [x] Full lifecycle (create → validate → refresh → revoke → validate-fails) via embedded API `P0` `fast`
- [x] Full lifecycle via server HTTP API `P1` `fast`
- [x] Session data persists across server restart (WAL durability) `P0` `fast`

#### Property

- [x] Random create/revoke sequences maintain consistent active session count (`proptest`) `P0` `extended`
- [x] No session ID collisions across 10,000+ random generations `P0` `extended`

#### Simulation

- [x] Crash recovery: no committed session is lost (`madsim` oracle assertion) `P0` `full`
- [x] TTL expiration correct under simulated clock skew / time drift `P1` `full`

#### Adversarial

- [x] Replayed session tokens rejected after revocation `P0` `fast`
- [x] Session fixation: pre-authentication session ID cannot be reused post-authentication `P0` `fast`
- [x] Enumeration resistance: responses for invalid, expired, and nonexistent session IDs are indistinguishable `P0` `fast`

#### Benchmark

- [x] Session lookup by ID: p50 < 10 μs, p99 < 100 μs (regression: +20%) `P0` `standard`
- [x] Session creation throughput: > 50,000 ops/sec/core `P1` `standard`

---

### Authorization (RBAC) Engine

Covers `src/rbac/` — the claims-based RBAC engine. See [AUTHORIZATION.md](./AUTHORIZATION.md) for the normative model; this section enumerates verification coverage.

#### Unit

- [ ] Permission string grammar: valid strings accepted, invalid rejected (empty, uppercase, leading digit, delimiter chars, length > 128) `P0` `fast`
- [ ] Role composition — transitive: `A → B → C` resolves all permissions from A, B, and C `P0` `fast`
- [ ] Role composition — cycle rejected: `A → B → A` returns `CycleDetected` `P0` `fast`
- [ ] Role composition — depth cap: 11-deep parent chain returns `DepthExceeded` `P0` `fast`
- [ ] Group membership — transitive: user in nested groups resolves to all containing groups `P0` `fast`
- [ ] Group membership — cycle rejected: `G1 ∈ G2 ∈ G1` returns `CycleDetected` `P0` `fast`
- [ ] Group caps: depth > 10 or breadth > 1000 returns the corresponding error `P0` `fast`

#### Integration

- [ ] Create role → assign to user → resolve → permissions present `P0` `fast`
- [ ] Create role chain A→B→C → resolve → all permissions present `P0` `fast`
- [ ] Group-assigned role: add user to group, assign role to group, resolve → user gets role's permissions `P0` `fast`
- [ ] Realm-scoped vs org-scoped assignment: token without `oid` excludes org-scoped permissions `P0` `fast`
- [ ] Scope request narrows permissions: `scope=docs` intersects resolved set with `docs.*` mapping `P0` `fast`

#### Property

- [ ] Random role DAGs (no cycles) produce correct reachability results (`proptest`) `P0` `extended`
- [ ] Random group graphs (no cycles) produce correct transitive membership (`proptest`) `P0` `extended`
- [ ] Random assign / unassign sequences maintain invariants (no orphaned permissions, no duplicate assignments) `P0` `extended`

#### Adversarial

- [ ] Invalid permission strings rejected at role creation (ungrammatical, reserved namespace abuse) `P0` `fast`
- [ ] Cross-realm permission leak prevented: resolving in realm B ignores realm A roles and groups `P0` `fast`
- [ ] Reserved namespace (`hearth.*`) refuses operator-defined role permissions `P0` `fast`
- [ ] Token-size cap exceeded: issuance refused with structured error naming the violating bound `P0` `fast`

#### Benchmark

- [ ] `resolve_permissions` (off the hot path, at token issue): p50 < 100 μs, p99 < 1 ms for a typical user (5 roles, 10 groups) `P0` `standard`
- [ ] JWT claim lookup (`hasPermission` on a decoded token): p99 < 1 μs (hashset `contains`) `P0` `standard`

---

### JWT / Tokens

#### Unit

- [x] Issue JWT with correct standard claims (`sub`, `iss`, `aud`, `exp`, `iat`) `P0` `fast`
- [x] Validate JWT: correct signature returns success with parsed claims `P0` `fast`
- [x] Reject expired, tampered-payload, and wrong-signing-key JWTs `P0` `fast`
- [x] Token refresh issues new JWT with extended expiration `P0` `fast`
- [x] JWKS endpoint returns correct public keys in standard format `P0` `fast`

#### Integration

- [x] Token issuance and validation round-trip via public API `P0` `fast`
- [x] Token refresh flow end-to-end (issue → expire → refresh → validate) `P0` `fast`

#### Fuzz

- [x] Arbitrary bytes to JWT parsing (header, payload, signature) never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [x] `alg=none` attack: unsigned token rejected regardless of claims `P0` `fast`
- [x] RSA/HMAC key confusion: HMAC-signed token with RSA public key as secret rejected `P0` `fast`
- [x] Modified `exp`, `iss`, or `aud` claims detected and rejected on validation `P0` `fast`
- [x] Nonce reuse in token requests detected (when nonce enforcement enabled) `P1` `fast`

#### Benchmark

- [x] Token validation (JWT verify + session lookup): p50 < 50 μs, p99 < 500 μs (regression: +20%) `P0` `standard`
- [x] Token issuance (full OAuth2 flow): p50 < 1 ms, p99 < 5 ms (regression: +20%) `P0` `standard`

---

### OIDC (Authorization Code Flow)

#### Unit

- [x] Generate authorization code with correct parameters (client_id, redirect_uri, scope, state) `P0` `fast`
- [x] Exchange valid authorization code for access + ID tokens `P0` `fast`
- [x] Authorization code single-use: second exchange attempt rejected `P0` `fast`
- [x] Authorization code expiration: exchange after timeout rejected `P0` `fast`
- [x] Discovery document at `.well-known/openid-configuration` returns correct metadata `P0` `fast`

#### Integration

- [x] Full authorization code flow via embedded API (authorize → exchange → validate) `P0` `fast`
- [x] Full authorization code flow via HTTP endpoints `P1` `fast`
- [x] PKCE (S256): code challenge generated, code verifier validated on exchange `P0` `fast`

#### Fuzz

- [x] Arbitrary bytes to OIDC authorization/token request parsers never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [x] Authorization code reuse and injection attacks rejected `P0` `fast`
- [x] Open redirect via `redirect_uri` manipulation: non-registered URIs rejected `P0` `fast`
- [x] CSRF prevention: missing or invalid `state` parameter causes flow rejection `P0` `fast`

#### Conformance

- [x] Discovery endpoint conforms to OpenID Connect Discovery 1.0 specification `P1` `full`
- [x] Token endpoint behavior conforms to OAuth 2.0 (RFC 6749) token exchange spec `P1` `full`

#### Benchmark

- [x] Authorization code exchange latency: p50 < 1 ms, p99 < 5 ms (regression: +20%) `P1` `standard`

---

### Configuration

#### Unit

- [x] Parse valid TOML/YAML server configuration file `P0` `fast`
- [x] Reject invalid configuration with descriptive, actionable error messages `P0` `fast`
- [x] Default values applied correctly for all omitted optional fields `P0` `fast`
- [x] `--dev` flag applies development-mode defaults (in-memory, relaxed security, test users) `P0` `fast`

#### Fuzz

- [x] Arbitrary bytes to configuration parser never panic (`cargo-fuzz`) `P0` `extended`

---

### CLI Tool

#### Integration

- [x] `hearth serve --dev` starts server and accepts connections `P0` `fast`
- [x] CLI management commands (`realm create`, `app create`) succeed against running server `P1` `fast`
- [x] CLI exits with appropriate non-zero error codes on invalid input or unreachable server `P0` `fast`

---

### End-to-End Flows

#### Integration

- [x] Developer on-ramp: start server → create realm → create app → complete OIDC login `P0` `fast`
- [x] User lifecycle: register → authenticate → receive session → validate token `P0` `fast`
- [x] Auth + authz: authenticate → assign role → issue token → verify permission claim grants action `P0` `fast`
- [x] Cascading invalidation: delete user → sessions invalidated → token validation fails `P0` `fast`

---

### Cross-Cutting Concerns

#### Adversarial

- [x] All API error responses leak no internal state (no stack traces, internal paths, or query details) `P0` `fast`
- [x] Constant-time comparisons used for all secret-derived values (tokens, session IDs, auth codes) `P0` `fast`
- [x] No credential material, tokens, or session IDs appear in log output at any log level `P0` `fast`
- [x] Sensitive data (passwords, keys, tokens) zeroed from memory after use `P0` `fast`
- [x] Input size limits enforced across all API endpoints (request body, header, URL length) `P0` `fast`

---

## Phase 1: Production Single-Node

### Phase 1 Progress Matrix

Phase 1 scenario counts by module and testing layer. `0/N` = completed/total. `--` = not applicable.

| Module | Unit | Integration | Property | Fuzz | Simulation | Adversarial | Conformance | Benchmark | **Total** |
|--------|------|-------------|----------|------|------------|-------------|-------------|-----------|-----------|
| OAuth 2.0 Complete | 5/5 | 3/3 | 2/2 | -- | -- | 3/3 | 2/2 | 2/2 | **17/17** |
| WebAuthn / Passkeys | 5/5 | 2/2 | -- | 1/1 | -- | 3/3 | 1/1 | -- | **12/12** |
| Magic Link / Passwordless | 4/4 | 2/2 | -- | -- | -- | 2/2 | -- | -- | **8/8** |
| TOTP / MFA | 5/5 | 3/3 | 1/1 | -- | -- | 2/2 | -- | -- | **11/11** |
| Multi-Tenancy | 5/5 | 3/3 | 3/3 | -- | 2/2 | 3/3 | -- | -- | **16/16** |
| RBAC Authorization (Full) | 5/5 | 3/3 | 2/2 | -- | -- | 2/2 | -- | 2/2 | **14/14** |
| Admin API | 3/3 | 4/4 | -- | -- | -- | 3/3 | -- | -- | **10/10** |
| Audit Logging | 4/4 | 3/3 | 2/2 | -- | 2/2 | 1/1 | -- | -- | **12/12** |
| TLS Termination | 3/3 | 3/3 | -- | -- | -- | 2/2 | -- | -- | **8/8** |
| SDK Integration (TS & Go) | -- | 6/6 | -- | -- | -- | -- | -- | -- | **6/6** |
| OIDC Conformance | -- | -- | -- | -- | -- | -- | 5/5 | -- | **5/5** |
| Proto & API Contract | 5/5 | -- | -- | -- | -- | -- | -- | -- | **5/5** |
| Phase 1 E2E Flows | -- | 4/4 | -- | -- | -- | -- | -- | -- | **4/4** |
| Phase 1 Cross-Cutting | -- | -- | -- | -- | -- | 3/3 | -- | 2/2 | **5/5** |
| **Column Total** | **40/44** | **34/36** | **10/10** | **1/1** | **4/4** | **22/24** | **8/8** | **6/6** | **133/133** |

> **Note:** Counts reflect the post-RBAC-migration plan. Simulation scenarios related to the removed Zanzibar watch/cache surfaces (`cache_stampede`, `watch_partition`) are dropped; RBAC resolution is synchronous with no equivalent simulation surface. Consider re-adding one concurrent-role-assignment property test during implementation.

---

### OAuth 2.0 Complete

#### Unit

- [x] Client credentials grant issues access token with correct scope and expiration `P0` `fast`
- [x] Device authorization (RFC 8628) generates user code and device code with correct polling interval `P0` `fast`
- [x] Refresh token rotation issues new refresh + access token pair and invalidates old refresh token `P0` `fast`
- [x] Token revocation (RFC 7009) invalidates access and refresh tokens; subsequent use rejected `P0` `fast`
- [x] Token introspection (RFC 7662) returns active/inactive status with correct metadata `P0` `fast`

#### Integration

- [x] Full client credentials flow via embedded API: register client → request token → validate → revoke `P0` `fast`
- [x] Full device authorization flow: device code request → user approval → token poll → access granted `P0` `fast`
- [x] Refresh token rotation end-to-end: issue → expire access → refresh → validate new token `P0` `fast`

#### Property

- [x] Random sequences of token issuance, refresh, and revocation maintain consistent active token set (`proptest`) `P0` `extended`
- [x] Refresh token rotation: no two valid refresh tokens exist simultaneously for the same grant (`proptest`) `P0` `extended`

#### Adversarial

- [x] Refresh token rotation theft detection: reuse of rotated-out refresh token revokes entire grant family `P0` `fast`
- [x] Client credentials with invalid or expired client secret rejected with generic error `P0` `fast`
- [x] Device authorization polling faster than `interval` returns `slow_down` error per RFC 8628 `P1` `fast`

#### Conformance

- [x] Token introspection response conforms to RFC 7662 (required fields, active boolean semantics) `P1` `full`
- [x] Device authorization flow conforms to RFC 8628 (user_code format, polling behavior, error codes) `P1` `full`

#### Benchmark

- [x] Client credentials token issuance: p50 < 500 μs, p99 < 2 ms (regression: +20%) `P0` `standard`
- [x] Token introspection: p50 < 50 μs, p99 < 500 μs (regression: +20%) `P0` `standard`

---

### WebAuthn / Passkeys

#### Unit

- [x] Registration ceremony: generate challenge, parse attestation response, store credential `P0` `fast`
- [x] Authentication ceremony: generate challenge, verify assertion response, update sign counter `P0` `fast`
- [x] Multi-credential support: user registers multiple passkeys, each authenticates independently `P0` `fast`
- [x] Resident key (discoverable credential) registration and username-less authentication `P0` `fast`
- [x] Attestation format validation: packed, TPM, and none attestation types handled correctly `P1` `fast`

#### Integration

- [x] Full registration + authentication lifecycle via embedded API `P0` `fast`
- [x] Credential management: register → authenticate → add second key → revoke first key → authenticate with second `P0` `fast`

#### Fuzz

- [x] Arbitrary bytes to CBOR attestation/assertion parser never panic (`cargo-fuzz`) `P0` `extended`

#### Adversarial

- [x] Sign counter replay: assertion with non-incrementing counter rejected (cloned authenticator detection) `P0` `fast`
- [x] RP ID mismatch: assertion from wrong relying party origin rejected `P0` `fast`
- [x] Tampered client data JSON: modified challenge or origin in clientDataJSON causes verification failure `P0` `fast`

#### Conformance

- [x] WebAuthn Level 2 registration and authentication ceremony conformance `P1` `full`

---

### Magic Link / Passwordless

#### Unit

- [x] Generate magic link token bound to email with correct expiration `P0` `fast`
- [x] Validate magic link token: correct token returns associated user `P0` `fast`
- [x] Expired magic link token rejected with appropriate error `P0` `fast`
- [x] Magic link token is single-use: second validation attempt rejected `P0` `fast`

#### Integration

- [x] Full passwordless flow via embedded API: request link → validate token → receive session `P0` `fast`
- [x] Magic link with existing user authenticates; with new email triggers account creation `P1` `fast`

#### Adversarial

- [x] Rate limiting: excessive magic link requests for same email throttled `P0` `fast`
- [x] Enumeration resistance: response is identical whether email exists or not `P0` `fast`

---

### TOTP / MFA

#### Unit

- [x] Generate TOTP secret with correct provisioning URI (issuer, account, algorithm, digits, period) `P0` `fast`
- [x] Validate TOTP code for current time window succeeds `P0` `fast`
- [x] TOTP time window tolerance: codes for T-1 and T+1 windows accepted `P0` `fast`
- [x] Generate recovery codes: correct count, sufficient entropy, each usable exactly once `P0` `fast`
- [x] Recovery code redemption: valid code succeeds; reused code rejected `P0` `fast`

#### Integration

- [x] MFA enrollment flow: enable TOTP → verify setup code → login requires MFA → provide code → session issued `P0` `fast`
- [x] Recovery code flow: lose authenticator → use recovery code → authenticate → re-enroll TOTP `P0` `fast`
- [x] MFA disable flow: authenticated user disables MFA → subsequent login no longer requires second factor `P0` `fast`

#### Property

- [x] Random clock offsets within tolerance window always validate; offsets outside window always reject (`proptest`) `P0` `extended`

#### Adversarial

- [x] TOTP brute-force protection: excessive failed attempts within window trigger lockout `P0` `fast`
- [x] TOTP replay protection: same code cannot be used twice within the same time window `P0` `fast`

---

### Multi-Tenancy

#### Unit

- [x] Create realm with configuration returns assigned RealmId `P0` `fast`
- [x] Realm-scoped user creation: users bound to realm; cross-realm lookup returns not-found `P0` `fast`
- [x] Per-realm signing keys: each realm gets independent key pair for token signing `P0` `fast`
- [x] Realm configuration update: changes to session TTL, password policy apply only to target realm `P0` `fast`
- [x] Cascading realm deletion: removing realm purges all users, sessions, credentials, groups, roles, and role assignments `P0` `fast`

#### Integration

- [x] Full realm lifecycle via embedded API: create → configure → create users → delete realm → verify cleanup `P0` `fast`
- [x] Multi-realm token issuance: tokens from realm A are not valid in realm B `P0` `fast`
- [x] Realm-scoped OIDC: discovery documents and JWKS endpoints differ per realm `P0` `fast`

#### Property

- [x] Random operations across N realms never produce cross-realm data leaks (`proptest`) `P0` `extended`
- [x] Realm key rotation under concurrent token issuance: all in-flight tokens remain valid (`proptest`) `P0` `extended`
- [x] Random create/delete realm sequences maintain consistent realm count and clean storage (`proptest`) `P0` `extended`

#### Simulation

- [x] Crash during cascading realm deletion: recovery completes deletion or fully rolls back (`madsim`) `P0` `full`
- [x] Concurrent realm operations under simulated I/O delays produce no data corruption (`madsim`) `P1` `full`

#### Adversarial

- [x] Cross-realm session injection: session ID from realm A rejected when presented to realm B `P0` `fast`
- [x] Realm ID spoofing: forged RealmId in request path rejected by ownership validation `P0` `fast`
- [x] Realm enumeration resistance: responses for nonexistent realms are indistinguishable from forbidden `P0` `fast`

---

### RBAC Authorization (Full)

Phase 1 extends the Phase 0 RBAC engine with group nesting, role composition, org-scoped assignments, scope → permission mapping, and declarative YAML-based role/permission config. See [AUTHORIZATION.md](./AUTHORIZATION.md) for the normative model.

#### Unit

- [ ] Group nesting: user in `G1 ∈ G2 ∈ G3` resolves to membership in all three `P0` `fast`
- [ ] Role composition: role with multiple parents unions all ancestor permissions; deduplicates `P0` `fast`
- [ ] Org-scoped assignment: `scope=Org(oid)` applies only when token carries matching `oid` `P0` `fast`
- [ ] Scope → permission mapping: realm config defines `scope=docs` → `docs.*`; token request narrows claim set accordingly `P0` `fast`
- [ ] Declarative YAML reconciliation: realm config with roles/groups/scopes creates or updates storage idempotently on startup `P0` `fast`

#### Integration

- [ ] First-user bootstrap: first user created in a fresh realm receives `realm.admin`; subsequent users get no default assignment `P0` `fast`
- [ ] `GET /v1/me/permissions` returns live-resolved permission set matching the most recent JWT for the same user `P0` `fast`
- [ ] User deletion cascades RBAC state: all role assignments and group memberships for the deleted user are purged `P0` `fast`

#### Property

- [ ] Random role-DAG + group-graph combinations produce correct resolved permission sets (`proptest`) `P0` `extended`
- [ ] Random assign / unassign / add-member / remove-member sequences preserve realm isolation and invariants (`proptest`) `P0` `extended`

#### Adversarial

- [ ] Reserved-namespace enforcement: operator-created role with `hearth.*` permission rejected at API `P0` `fast`
- [ ] Size-cap attack: assign enough roles/groups to exceed token size; issuance fails with named limit, no oversize token escapes `P0` `fast`

#### Benchmark

- [ ] `resolve_permissions` (off hot path, at token issue): p50 < 100 μs, p99 < 1 ms for a typical user (5 roles, 10 groups, 30 permissions) `P0` `standard`
- [ ] JWT claim lookup (`hasPermission` on a decoded token, hot path-adjacent): p99 < 1 μs `P0` `standard`

---

### Admin API

#### Unit

- [x] Admin role enforcement: only users with admin role can access management endpoints `P0` `fast`
- [x] Pagination and filtering: list endpoints return correct pages with cursor-based pagination `P0` `fast`
- [x] Bulk operations: batch user create/disable processes all entries and returns per-item results `P1` `fast`

#### Integration

- [x] REST CRUD for users: create, read, update, disable, list via admin endpoints `P0` `fast`
- [x] REST CRUD for realms: create, read, update, delete via admin endpoints `P0` `fast`
- [x] REST CRUD for applications: create, read, update, delete via admin endpoints `P0` `fast`
- [x] Admin audit trail: all admin mutations appear in audit log with actor identity `P0` `fast`

#### Adversarial

- [x] Privilege escalation: non-admin user accessing admin endpoints receives 403 with no data leak `P0` `fast`
- [x] Admin endpoint rate limiting: excessive requests from single admin trigger throttling `P1` `fast`
- [x] Mass enumeration via admin listing: response times constant regardless of result count (no timing leak) `P0` `fast`

---

### Audit Logging

#### Unit

- [x] Security-critical mutations emit structured audit events with correct fields (actor, action, resource, timestamp) `P0` `fast`
- [x] Audit log is append-only: no API to update or delete audit entries `P0` `fast`
- [x] Audit log query by time range, actor, action type returns correct results `P0` `fast`
- [x] Audit events include realm context: all entries scoped to originating realm `P0` `fast`

#### Integration

- [x] Full audit lifecycle: perform mutations → query audit log → verify complete event trail `P0` `fast`
- [x] Audit log persistence: entries survive server restart `P0` `fast`
- [x] Compliance query: retrieve all authentication events for a user within date range `P1` `fast`

#### Property

- [x] Random mutation sequences produce audit logs where event count equals mutation count (`proptest`) `P0` `extended`
- [x] Audit log ordering: events are strictly ordered by timestamp across concurrent writers (`proptest`) `P0` `extended`

#### Simulation

- [x] Crash during audit write: recovery produces no partial or duplicate entries (`madsim`) `P0` `full`
- [x] Audit log integrity under sustained write load: no events lost or reordered (`madsim`) `P0` `full`

#### Adversarial

- [x] Audit log tamper detection: modification of stored entries detected on read `P0` `fast`

---

### TLS Termination

#### Unit

- [x] Load TLS certificate and private key from PEM files `P0` `fast`
- [x] Certificate hot-reload: new cert loaded without server restart or connection drop `P0` `fast`
- [x] TLS 1.3 negotiation: server correctly negotiates TLS 1.3 with compliant client `P0` `fast`

#### Integration

- [x] HTTPS endpoint serves valid TLS: client connects and completes handshake `P0` `fast`
- [x] HTTP to HTTPS redirect: plaintext request receives 301 redirect to HTTPS equivalent `P0` `fast`
- [x] Mutual TLS (mTLS): server requests and validates client certificate when configured `P1` `fast`

#### Adversarial

- [x] TLS downgrade prevention: connection attempts with TLS 1.1 or below rejected `P0` `fast`
- [x] Weak cipher rejection: server refuses connections using deprecated cipher suites `P0` `fast`

---

### SDK Integration (TypeScript & Go)

#### Integration

- [x] TypeScript SDK: complete authorization code flow (authorize → exchange → validate → refresh) `P0` `fast`
- [x] TypeScript SDK: admin CRUD operations (create/read/update/delete users and realms) `P0` `fast`
- [x] TypeScript SDK: JWKS validation — tokens verified using fetched public keys `P0` `fast`
- [x] Go SDK: complete authorization code flow (authorize → exchange → validate → refresh) `P0` `fast`
- [x] Go SDK: admin CRUD operations (create/read/update/delete users and realms) `P0` `fast`
- [x] Go SDK: transparent token refresh — expired access token triggers automatic refresh `P0` `fast`

---

### OIDC Conformance

#### Conformance

- [x] OpenID Connect Core 1.0: all required claims present, correct ID token signing, scope handling `P0` `full`
- [x] OpenID Connect Discovery 1.0: well-known endpoint returns all required metadata fields `P0` `full`
- [x] OpenID Connect Dynamic Client Registration 1.0: register, read, and update client metadata `P1` `full`
- [x] UserInfo endpoint: returns correct claims for authenticated user with valid access token `P0` `full`
- [x] ID Token validation: all required claims (iss, sub, aud, exp, iat, nonce) verified `P0` `full`

---

### Proto & API Contract Validation

#### Unit

- [x] `buf lint` passes on all `.proto` files with STANDARD rule set `P0` `fast`
- [x] `buf breaking` detects no backwards-incompatible proto changes vs main branch `P0` `fast`
- [x] Generated SDK types (TypeScript + Go) are up-to-date with `.proto` definitions (`buf generate --diff`) `P0` `fast`
- [x] Proto-to-domain conversion layer compiles after proto field changes (exhaustive struct construction catches drift) `P0` `fast`
- [x] pbjson int64-as-string coercion: all HTTP responses pass through `proto_to_rest_json()` so REST clients receive numeric JSON `P0` `fast`

---

### Phase 1 End-to-End Flows

#### Integration

- [x] Keycloak migration: import users/clients from Keycloak export → authenticate migrated user → verify session `P1` `fast`
- [x] MFA enrollment + login: register → enable TOTP → authenticate with password + TOTP → receive session `P0` `fast`
- [x] Passkey-only authentication: register passkey → passwordless login → receive session → validate token `P0` `fast`
- [x] Multi-realm isolation round-trip: create 2 realms → create users in each → verify complete data isolation `P0` `fast`

---

### Phase 1 Cross-Cutting Concerns

#### Adversarial

- [x] Error response sanitization: Phase 1 endpoints leak no internal state (no stack traces, query details, or internal paths) `P0` `fast`
- [x] Zeroize enforcement: all Phase 1 sensitive types (TOTP secrets, magic link tokens, recovery codes) zeroed after use `P0` `fast`
- [x] Input size limits: Phase 1 endpoints enforce request body, header, and URL length limits `P0` `fast`

#### Benchmark

- [x] Admin user listing: p50 < 5 ms, p99 < 50 ms for 10K users with pagination (regression: +20%) `P0` `standard`
- [x] Audit log query: p50 < 10 ms, p99 < 100 ms for 100K entries with time range filter (regression: +20%) `P0` `standard`

---

## Phases 2–3+

High-level test categories for future phases. Individual checkboxes will be expanded as each phase begins development.

### Phase 2: Production Clustering

- **Raft consensus** — leader election, log replication, snapshot recovery (Unit, Simulation, Benchmark)
- **Network partition handling** — split-brain prevention, quorum enforcement (Simulation)
- **SAML 2.0** — SP and IdP flows, XML signature validation (Integration, Fuzz, Conformance)
- **SCIM 2.0** — user provisioning, bulk operations (Integration, Conformance)
- **Migration tools** — Auth0 and Clerk import (Integration)
- **Multi-node integration** — replication consistency, cross-node permission checks, failover (Integration, Simulation, Benchmark)

### Phase 3+: Scale and Ecosystem

- **Multi-region replication** — configurable consistency, latency-optimized routing (Simulation, Benchmark)
- **Hearth Cloud** — managed offering, realm provisioning, billing integration (Integration)
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

### Phase 1 Benchmark Targets

| Operation | p50 | p99 | Throughput Target |
|-----------|-----|-----|-------------------|
| Client credentials token issuance | < 500 μs | < 2 ms | — |
| Token introspection | < 50 μs | < 500 μs | — |
| Permission resolution at token issue | < 100 μs | < 1 ms | — |
| JWT claim lookup (`hasPermission`) | — | < 1 μs | 10M+ ops/sec/core |
| Admin user listing (10K users) | < 5 ms | < 50 ms | — |
| Audit log query (100K entries) | < 10 ms | < 100 ms | — |

**Capacity targets** (single node):

| Metric | Target |
|--------|--------|
| Total managed users | 100M+ |
| Active sessions | 10M+ |
| Role assignments | 100M+ |
| Memory (1M hot users) | < 500 MB |
| Memory (10M hot users) | < 8 GB |
| Binary size | < 50 MB |
| Cold start to serving | < 2 seconds |

---

## Adversarial Test Categories Reference

All categories from TESTING.md §6, mapped to Phase 0 and Phase 1 modules where applicable.

| Category | Phase 0 Coverage | Phase 1 Coverage |
|----------|-----------------|------------------|
| Timing attacks | Credential Storage, Cross-Cutting Concerns | Admin API (enumeration timing) |
| Token forgery | JWT / Tokens (`alg=none`, key confusion, claim tampering) | OAuth 2.0 (rotation theft detection) |
| Privilege escalation | RBAC Engine (reserved namespace, role-composition cycles, cap enforcement) | Admin API (non-admin access), Multi-Tenancy (realm ID spoofing) |
| Replay attacks | Session Management (replayed tokens), OIDC (code reuse) | WebAuthn (sign counter replay), TOTP (code reuse), OAuth 2.0 (refresh reuse) |
| Input injection | User CRUD (null bytes, unicode), Cross-Cutting (size limits) | Phase 1 Cross-Cutting (size limits) |
| Credential stuffing | Credential Storage (rate limiting) | TOTP (brute-force lockout), Magic Link (rate limiting) |
| Enumeration attacks | — | Magic Link (email enumeration), Multi-Tenancy (realm enumeration) |
| Protocol downgrade | — | TLS Termination (downgrade prevention, weak ciphers) |
| Tamper detection | — | Audit Logging (tamper detection on read) |
