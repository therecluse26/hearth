## Summary

<!-- Describe what this PR changes and why. -->

---

## SDK conformance checklist

> **Required for all PRs that touch `sdks/`.** Skip with `N/A` if this PR does not modify SDK code.
> Spec reference: [docs/sdk-spec.md](../docs/sdk-spec.md)

- [ ] **Section 5 — Error types:** All 9 spec error type names are present (`ConfigurationError`, `DiscoveryError`, `JWKSFetchError`, `TokenExpiredError`, `TokenNotYetValidError`, `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`, `IntrospectionError`)
- [ ] **Section 4 — Claims API:** All required public Claims API methods are present (`subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scope`, `scopes`, `hasScope`, `hasRole`, `hasPermission`, `get`)
- [ ] **Section 11 — Secret hygiene:** No tokens, secrets, or credential values appear in error messages, log output, or stack traces
- [ ] **Section 2 — JWKS caching:** Caching follows the 5-rule contract (cache by `kid`, respect `Cache-Control`, re-fetch on cache miss, re-fetch on 401, 24 h max age)
- [ ] **Section 9 — Tests:** Tests cover JWKS key rotation and clock skew edge cases
- [ ] **Section 10 — Documentation:** README includes installation, quickstart, API reference, and troubleshooting sections
- [ ] **Section 8 — Changelog:** `CHANGELOG.md` is present and updated for this release

---

## Test plan

<!-- How did you verify this change? Link CI run or describe manual steps. -->

- [ ] CI passes (conformance check + unit tests)
- [ ] Integration tests run against a live Hearth instance (if applicable)
