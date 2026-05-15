# Changelog

All notable changes to `hearth-rust` are documented here.

## [Unreleased]

### Added
- Initial SDK implementation conforming to the [Hearth SDK Common Specification](../../docs/sdk-spec.md).
- All 9 required error types from spec §5 added to `HearthError` enum: `ConfigurationError`, `DiscoveryError`, `JWKSFetchError`, `TokenExpiredError`, `TokenNotYetValidError`, `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`, `IntrospectionError`.
- `Claims` struct (spec §4) with typed accessors: `subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scopes`, `hasScope`, `hasRole`, `hasPermission`.
