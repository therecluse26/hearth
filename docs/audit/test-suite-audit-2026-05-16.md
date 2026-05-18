# Test-Suite Audit — 2026-05-16

Audit of the Hearth test suite against the anti-pattern taxonomy defined in
[HEA-565](/HEA/issues/HEA-565). Mechanical sweep run on branch `chore/test-audit`
(index rebuild: 2026-05-17T00:33:47Z, 277 Rust files, 146 k LOC).

---

## Summary table

| Category | Description | Total hits | Improvable | False-conf. | Stale | Legitimate |
|----------|-------------|------------|------------|-------------|-------|------------|
| A.1 `is_ok()` | `assert!(...is_ok())` no value check | 10 | 0 | 0 | 0 | 10 |
| A.1 `is_err()` | `assert!(...is_err())` no variant check | 28 | 14 | 0 | 0 | 14 |
| A.2 | `.unwrap()`/`.expect()` as terminal, no follow-up assert | 4 | 4 | 0 | 0 | 0 |
| A.3 | Test functions with zero `assert*!` macros | 4 | 4 | 0 | 0 | 0 |
| A.5 | `matches!(x, Ok(_))` / `matches!(x, Err(_))` broad | 0 | 0 | 0 | 0 | 0 |
| B.1 | `.ok();` / `let _ = …` discards in test bodies | 38 | 1 | 0 | 0 | 37 |
| B.2 | `unwrap_or_default()` / `or_default()` in test asserts | 5 | 2 | 0 | 0 | 3 |
| D.2 | `#[cfg(test)]` branches changing production behaviour | 98 | 0 | 0 | 0 | 98 |
| E.1 | `thread::sleep` / `tokio::time::sleep` in tests | 3 | 1 | 0 | 0 | 2 |
| F | Adversarial tests asserting only `is_err()`, no variant | 9 | 9 | 0 | 0 | 0 |
| I | `#[ignore]` with stale/outdated reason | 4 | 4 | 0 | 0 | 0 |

> **Note:** A.2 and A.3 overlap (same 4 tests). F is a subset of A.1 `is_err()`.  
> Total unique improvable findings: **27** across all categories.

---

## Findings

### A.1 — `assert!(...is_ok())` — no value check

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/rbac_p0_scenarios.rs:28` | `assert!(Permission::new("docs.read").is_ok())` | legitimate | Constructor returns `Ok(Permission)`; happy-path check is the goal. No payload to further inspect. |
| `tests/rbac_p0_scenarios.rs:29` | `assert!(Permission::new("org.billing.view").is_ok())` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:30` | `assert!(Permission::new("a.b.c.d").is_ok())` | legitimate | Same. |
| `tests/rbac_registry_validation.rs:88` | `assert!(reg.validate().is_ok(), "valid registry must pass")` | legitimate | `validate()` returns `Ok(())`; nothing to destructure. |
| `tests/rbac_registry_validation.rs:94` | `assert!(reg.validate().is_ok())` | legitimate | Same. |
| `tests/rbac_registry_validation.rs:136` | `assert!(reg.validate().is_ok())` | legitimate | Same. |
| `tests/rbac_registry_validation.rs:146` | `assert!(reg.validate().is_ok())` | legitimate | Same. |
| `tests/rbac_registry_validation.rs:302` | `assert!(reg.validate().is_ok(), "diamond-shaped DAG must pass")` | legitimate | Same. |
| `tests/realm_branding.rs:304` | `assert!(validate_email_template("verification", "").is_ok())` | legitimate | Validates empty template accepted; `Ok(())` has no payload. |
| `tests/realm_branding.rs:305` | `assert!(validate_email_template("password_reset", "Plain text…").is_ok())` | legitimate | Same. |

---

### A.1 — `assert!(...is_err())` — no variant check

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/federation_conformance.rs:158` | `assert!(verify_id_token_claims(…).is_err())` | improvable | Inconsistent: other tests in the same file use `assert!(matches!(…, Err(IdentityError::FederationTokenVerificationFailed)))`. Should match variant. |
| `tests/federation_conformance.rs:181` | `assert!(verify_id_token_claims(…).is_err())` | improvable | Same inconsistency. |
| `tests/federation_conformance.rs:204` | `assert!(verify_id_token_claims(…).is_err())` | improvable | Same inconsistency. |
| `tests/federation_conformance.rs:250` | `assert!(verify_id_token_claims(…).is_err())` | improvable | Same inconsistency. |
| `tests/oidc_conformance.rs:372` | `assert!(bad_result.is_err(), "userinfo with invalid token must fail")` | improvable | Security check; should pin the error variant (see also category F). |
| `tests/organizations.rs:691` | `assert!(result.is_err(), "revoked invitation should not be accepted")` | legitimate | Invitation-revocation check; descriptive message; error variant has no further useful info at this call site. |
| `tests/rbac_p0_scenarios.rs:44` | `assert!(Permission::new("docs").is_err())` | legitimate | Validation unit test; single error variant exists. |
| `tests/rbac_p0_scenarios.rs:45` | `assert!(Permission::new("nodot").is_err())` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:50` | `assert!(Permission::new("docs read").is_err(), "space")` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:51` | `assert!(Permission::new("docs/read").is_err(), "slash")` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:52` | `assert!(Permission::new("docs:read").is_err(), "colon")` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:149` | `assert!(Permission::new("").is_err(), "empty")` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:150` | `assert!(Permission::new("no-dot").is_err(), …)` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:151` | `assert!(Permission::new("has space.x").is_err(), …)` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:152` | `assert!(Permission::new("slash/x.y").is_err(), …)` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:153` | `assert!(Permission::new("colon:x.y").is_err(), …)` | legitimate | Same. |
| `tests/rbac_p0_scenarios.rs:155` | `assert!(Permission::new(&long).is_err(), "too long")` | legitimate | Same. |
| `tests/realm_branding.rs:254` | `assert!(result.is_err())` | improvable | Redundant: immediately followed by `result.expect_err(…)` which would panic anyway. Remove the first assert. |
| `tests/realm_branding.rs:282` | `assert!(result.is_err())` | improvable | Same pattern; remove or consolidate into `expect_err`. |
| `tests/realm_branding.rs:291` | `assert!(result.is_err())` | improvable | Sole check in this test — no variant, no message. |
| `tests/realm_branding.rs:297` | `assert!(result.is_err())` | improvable | Redundant before `expect_err`. |
| `tests/realms.rs:215` | `assert!(err.is_err(), "JWKS for nonexistent realm should fail")` | improvable | Should assert `Err(IdentityError::RealmNotFound)` to pin the failure mode. |
| `tests/tls.rs:343` | `assert!(result.is_err(), "request without client cert should fail")` | improvable | Security test; should verify specific TLS error variant (see also category F). |
| `tests/tokens.rs:292` | `assert!(result.is_err(), "issue tokens should fail for deleted user")` | improvable | Security path; should match `Err(IdentityError::UserNotFound)` (see also F). |
| `tests/tokens.rs:322` | `assert!(result.is_err(), "tampered token must be rejected")` | improvable | Security path; should match `Err(IdentityError::InvalidToken)` or equivalent (see also F). |
| `tests/tokens.rs:352` | `assert!(result.is_err(), "tampered refresh token must be rejected")` | improvable | Security path; same as above (see also F). |
| `tests/web_assets.rs:41` | `assert!(assert_bytes_sane(&tiny).is_err())` | legitimate | Internal test-helper validation; error variant conveys no useful info. |
| `tests/web_assets.rs:47` | `assert!(assert_bytes_sane(&bytes).is_err())` | legitimate | Same. |

---

### A.2 — `.unwrap()` / `.expect()` used as terminal, no follow-up `assert*!`

These four tests in `tests/realm_auth_policy.rs` use `.expect()` as their sole verification
mechanism. While `.expect()` does panic on `Err`, the success value is silently dropped and no
properties of the returned object are checked. Also flagged under A.3.

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/realm_auth_policy.rs:125` | `.expect("magic_link should succeed when allowed")` | improvable | Only checks the call doesn't error. No assertion on the returned token or that an email would be queued. |
| `tests/realm_auth_policy.rs:137` | `.expect("magic_link should succeed when …unconfigured")` | improvable | Same. |
| `tests/realm_auth_policy.rs:331` | `.expect("create_session should succeed: user has MFA enrolled")` | improvable | Session returned but not inspected (user_id, session_id). |
| `tests/realm_auth_policy.rs:356` | `.expect("passkey session should bypass mfa_required TOTP gate")` | improvable | Same; at minimum assert `session.user_id() == user.id()`. |

---

### A.3 — Test functions with zero `assert*!` macros

The four tests above (realm_auth_policy.rs) have no `assert*!` calls at all. The
`tests/federation_conformance.rs` flag in the plan was a **false positive** — the file
does contain `assert!` and `assert!(matches!(…))` throughout.

| File:Line | Function | Disposition | Rationale |
|-----------|----------|-------------|-----------|
| `tests/realm_auth_policy.rs:111` | `magic_link_allowed_when_in_allowed_methods` | improvable | Relies solely on `.expect()`. |
| `tests/realm_auth_policy.rs:129` | `magic_link_allowed_when_no_restriction` | improvable | Same. |
| `tests/realm_auth_policy.rs:316` | `mfa_required_allows_session_when_user_has_mfa` | improvable | Same. |
| `tests/realm_auth_policy.rs:335` | `mfa_required_passkey_satisfies_policy` | improvable | Same. |

---

### A.5 — `matches!(x, Ok(_))` / `matches!(x, Err(_))` broad matches

**0 sites found.** This pattern does not appear in the test suite.

---

### B.1 — `.ok();` / `let _ = …` discards in test bodies

38 total sites. 37 legitimate; 1 improvable.

**Legitimate patterns (representative sample):**

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/error_codes.rs:49,52` | `rx.await.ok(); …server.await.ok()` | legitimate | Server teardown; ignoring shutdown-channel result is intentional. |
| `tests/tls.rs:430` | `stream.shutdown().await.ok()` | legitimate | Stream close during cleanup. |
| `tests/tls.rs:171,228,296,346,448` | `let _ = tokio::time::timeout(…, server_handle).await` | legitimate | Server handle join during teardown; timeout value doesn't matter. |
| `tests/cli.rs:25,26` | `let _ = self.child.kill(); let _ = self.child.wait()` | legitimate | Drop impl for process guard; errors suppressed intentionally. |
| `tests/adversarial.rs:217` | `let _ = engine.verify_password(…)` | legitimate | Rate-limit budget exhaustion loop; result discarded intentionally. |
| `tests/grpc_rbac_admin.rs:165,199` | `let _ = ctx.svc.delete_role(…).await.expect("delete")` | legitimate | Delete RPC returns empty; `.expect()` covers the error path. |
| `tests/oauth_consent.rs:982,1036,1189` | `let _ = rig` (borrow suppression) | legitimate | Prevents partial-move lint; not discarding a result. |
| `tests/admin_realm.rs:116` | `let _ = RegistrationPolicy::Open` | legitimate | Lint suppression for unused import. |

**Improvable:**

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/self_registration.rs:242` | `let _ = harness.identity().register_user(…)` in loop body | improvable | Inside a rate-limit-consumption loop; should use `.unwrap_or_else(…)` or an explicit assert to verify the first N calls succeeded. |

---

### B.2 — `unwrap_or_default()` / `or_default()` in test asserts

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/certs_jwks.rs:69` | `.map(\|k\| k["alg"].as_str().unwrap_or_default())` | legitimate | Collecting algorithm strings; `None → ""` is expected for JWKS keys without alg. |
| `tests/security_phase_b.rs:445` | `SystemTime::now().duration_since(…).unwrap_or_default().as_micros()` | legitimate | Wall-clock helper; overflow path is unreachable in practice. |
| `tests/web_ui_account_sessions.rs:426` | `.and_then(\|v\| v.to_str().ok()).unwrap_or_default()` on Location header | improvable | Silently returns `""` if the header is absent; the follow-up `assert!(location.ends_with(…))` would still pass with `""`. Use `.expect("location header must be present")` instead. |
| `tests/web_ui_admin.rs:1407` | `set_cookie_with(&response, "hearth_ui_last_realm=").unwrap_or_default()` | improvable | Masks the case where the cookie is absent entirely; `assert!(…contains(…))` would vacuously succeed on `""`. Add an explicit presence check. |
| `tests/web_ui_admin.rs:1446` | `set_cookie_with(&response, "hearth_ui_last_realm=").unwrap_or_default()` | improvable | Same as above. |

---

### D.2 — `#[cfg(test)]` branches in `src/` that change production behaviour

**98 sites found; 98 legitimate.**

All occurrences are standard `#[cfg(test)] mod tests { … }` blocks at module end,
or isolated test-only helpers with no production code path:

- `src/storage/engine.rs:126` — `#[cfg(test)] pub(crate) fn test_config()`: provides fast-sync/small-threshold config for tests only. No production branch.
- `src/identity/webauthn.rs:947` — `#[cfg(test)] pub(crate) mod test_helper`: test utility module not compiled into production binary.
- `src/rbac/resolve.rs:21` — `#[cfg(test)] use super::types::Subject`: import gated to test compilation.

No production code path changes on `#[cfg(test)]` were found. All D.2 hits are legitimate.

---

### E.1 — `thread::sleep` / `tokio::time::sleep` in tests

| File:Line | Code Snippet | Disposition | Rationale |
|-----------|-------------|-------------|-----------|
| `tests/cli.rs:63` | `std::thread::sleep(Duration::from_millis(50))` | legitimate | Inside a TCP-connect retry loop polling for server readiness. Sleep is bounded by the loop. |
| `tests/oidc.rs:195` | `tokio::time::sleep(Duration::from_millis(50)).await` | legitimate | Same port-polling pattern. |
| `tests/tls.rs:201` | `tokio::time::sleep(std::time::Duration::from_millis(100)).await` | improvable | Fixed unconditional sleep: "Give the redirect server time to bind." Should be converted to a TCP-connect poll loop (like cli.rs:63) to avoid timing-dependent flakiness. |

---

### F — Adversarial tests asserting only `is_err()`, no variant match

All 9 sites are a subset of A.1 `is_err()` improvable hits above.

| File:Line | Test Name | Code Snippet | Disposition |
|-----------|-----------|-------------|-------------|
| `tests/federation_conformance.rs:158` | `rejects_audience_array_without_client` | `assert!(verify_id_token_claims(…).is_err())` | improvable — match `Err(IdentityError::FederationTokenVerificationFailed)` |
| `tests/federation_conformance.rs:181` | `rejects_missing_nonce_when_expected` | `assert!(verify_id_token_claims(…).is_err())` | improvable — same variant |
| `tests/federation_conformance.rs:204` | `rejects_exp_past_skew_tolerance` | `assert!(verify_id_token_claims(…).is_err())` | improvable — same variant |
| `tests/federation_conformance.rs:250` | `rejects_nbf_in_the_future_past_skew` | `assert!(verify_id_token_claims(…).is_err())` | improvable — same variant |
| `tests/oidc_conformance.rs:372` | `userinfo_endpoint_scoped_claims` | `assert!(bad_result.is_err(), "…")` | improvable — should pin auth error variant |
| `tests/tls.rs:343` | `mtls_rejects_missing_client_cert` | `assert!(result.is_err(), "…")` | improvable — should match TLS error variant |
| `tests/tokens.rs:292` | `issue_tokens_fails_for_deleted_user` | `assert!(result.is_err(), "…")` | improvable — match `Err(IdentityError::UserNotFound)` |
| `tests/tokens.rs:322` | `tampered_access_token_rejected` | `assert!(result.is_err(), "…")` | improvable — match `Err(IdentityError::InvalidToken)` |
| `tests/tokens.rs:352` | `tampered_refresh_token_rejected` | `assert!(result.is_err(), "…")` | improvable — match `Err(IdentityError::InvalidToken)` |

---

### I — `#[ignore]` markers with stale/outdated reason

4 tests carry `#[ignore = "HTTP layer not yet implemented"]` (or similar). The HTTP layer
**has** been implemented (hundreds of web/oauth/SCIM tests exercise it). However,
`TestHarness::server()` still returns `ServerNotAvailable` (asserted in
`test_harness.rs:140-151`). The ignore reason is therefore partially outdated: the feature
exists but the test harness hasn't been wired to it. Disposition: improvable (update the
ignore message to reflect the actual blocker, then wire the harness).

| File:Line | Ignored Test | Current Reason | Disposition |
|-----------|-------------|----------------|-------------|
| `tests/sessions.rs:82` | `session_full_lifecycle_server` | `"HTTP layer not implemented"` | improvable — HTTP exists; `TestHarness::server()` needs wiring |
| `tests/test_harness.rs:47` | `server_mode_starts_and_stops_cleanly` | `"HTTP layer not yet implemented"` | improvable — same |
| `tests/test_harness.rs:92` | `dual_mode_server` | `"HTTP layer not yet implemented"` | improvable — same |
| `tests/users.rs:294` | `server_mode_crud` | `"HTTP protocol layer not yet implemented"` | improvable — same; test body is also a placeholder stub |

---

## Notable observations

1. **federation_conformance.rs inconsistency (F):** The same file has 4 tests that
   use proper `assert!(matches!(…, Err(IdentityError::FederationTokenVerificationFailed)))`
   and 4 that use bare `assert!(…is_err())`. The 4 bare ones were likely written before the
   variant was settled. Fixing them is a low-effort, high-value improvement.

2. **realm_auth_policy.rs (A.2/A.3):** All 4 zero-`assert*!` tests are happy-path
   policy checks that could be strengthened by asserting on the returned session/token
   value — even a simple `assert_eq!(session.user_id(), user.id())` closes the gap.

3. **A.5 (broad `matches!`) is a non-issue:** Zero occurrences found. The codebase uses
   proper variant-pinning in `matches!` calls throughout.

4. **D.2 is clean:** All `#[cfg(test)]` usage in `src/` is standard unit-test module
   gating. No production code path is gated by a test flag.

5. **#[ignore] backlog (I):** The 4 ignored tests represent a real coverage gap — the
   `TestHarness::server()` mode is a stub. Once wired, these tests would exercise the
   full HTTP stack via the same assertions already covering embedded mode, which is the
   intended dual-mode test strategy.

---

*Generated by QA agent (HEA-566) on 2026-05-16. Sweep tooling: mcp__reflex__search_regex + mcp__reflex__search_code against index rebuilt at 2026-05-17T00:33:47Z.*
