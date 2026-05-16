# Hearth REST API Error Codes

All Hearth REST error responses include a stable `error_code` field alongside the human-readable `error` message. Clients should branch on `error_code`, not on the `error` string.

## Response Shape

```json
{ "error": "token expired", "error_code": "HEARTH_TOKEN_EXPIRED" }
```

For server-side (5xx) errors, `error_code` is `null` — internal detail is never exposed:

```json
{ "error": "internal error", "error_code": null }
```

## Error Code Registry

### Token Errors

| Code | Meaning |
|------|---------|
| `HEARTH_TOKEN_EXPIRED` | JWT or session token has expired. Refresh or re-authenticate. |
| `HEARTH_TOKEN_REVOKED` | Token has been explicitly revoked. Re-authenticate. |
| `HEARTH_TOKEN_INVALID` | Malformed token or bad signature. |
| `HEARTH_TOKEN_TOO_LARGE` | Resolved claim set exceeded a configured size limit. |

### Authentication / Credential Errors

| Code | Meaning |
|------|---------|
| `HEARTH_INVALID_CREDENTIAL` | Wrong password or credential. |
| `HEARTH_INVALID_CLIENT` | OAuth client not recognized or misconfigured. |
| `HEARTH_INVALID_GRANT` | Authorization grant is invalid, expired, or already consumed. |
| `HEARTH_INVALID_REDIRECT_URI` | Redirect URI does not match any registered URI for the client. |
| `HEARTH_UNSUPPORTED_GRANT_TYPE` | Grant type not supported for this client. |

### MFA

| Code | Meaning |
|------|---------|
| `HEARTH_MFA_REQUIRED` | Authentication requires an MFA step before a session can be issued. |
| `HEARTH_MFA_INVALID_CODE` | TOTP or recovery code is incorrect. |
| `HEARTH_MFA_NOT_ENABLED` | MFA is not enrolled for this user. |
| `HEARTH_MFA_ALREADY_ENABLED` | MFA is already enrolled; disable before re-enrolling. |

### WebAuthn / Passkeys

| Code | Meaning |
|------|---------|
| `HEARTH_WEBAUTHN_REGISTRATION_FAILED` | WebAuthn registration ceremony failed. |
| `HEARTH_WEBAUTHN_AUTHENTICATION_FAILED` | WebAuthn authentication ceremony failed. |
| `HEARTH_WEBAUTHN_CREDENTIAL_NOT_FOUND` | Referenced WebAuthn credential does not exist. |
| `HEARTH_INVALID_ATTESTATION` | Attestation provided during registration is invalid or unsupported. |
| `HEARTH_INVALID_ASSERTION` | Assertion provided during authentication is invalid. |

### Device Authorization Flow

| Code | Meaning |
|------|---------|
| `HEARTH_AUTHORIZATION_PENDING` | Device authorization is waiting for user approval. Keep polling. |
| `HEARTH_SLOW_DOWN` | Device is polling too frequently. Increase polling interval. |
| `HEARTH_DEVICE_CODE_EXPIRED` | Device authorization code has expired. Restart the flow. |
| `HEARTH_DEVICE_CODE_DENIED` | Device authorization was denied by the user. |

### Rate Limiting / Account Lockout

| Code | Meaning |
|------|---------|
| `HEARTH_RATE_LIMITED` | Request rate limit exceeded, or account temporarily locked after repeated failed attempts. |

### Account State

| Code | Meaning |
|------|---------|
| `HEARTH_EMAIL_UNVERIFIED` | Email address has not been verified. |
| `HEARTH_PASSWORD_EXPIRED` | Password has expired and must be reset before logging in. |
| `HEARTH_PASSWORD_REUSED` | New password matches a previously used password. |
| `HEARTH_AUTH_METHOD_NOT_ALLOWED` | Authentication method is not permitted by realm policy. |

### Resource Not Found

| Code | Meaning |
|------|---------|
| `HEARTH_NOT_FOUND` | Requested resource (user, client, etc.) does not exist. |
| `HEARTH_SESSION_NOT_FOUND` | Session not found, expired, or revoked. |

### Realm State

| Code | Meaning |
|------|---------|
| `HEARTH_REALM_SUSPENDED` | Realm is suspended; all operations are denied. |

### Input Validation

| Code | Meaning |
|------|---------|
| `HEARTH_INVALID_INPUT` | Request input failed validation. |

### Conflicts / Duplicates

| Code | Meaning |
|------|---------|
| `HEARTH_DUPLICATE_EMAIL` | A user with this email already exists in the realm. |
| `HEARTH_DUPLICATE_REALM_NAME` | A realm with this name already exists. |

### Organizations

| Code | Meaning |
|------|---------|
| `HEARTH_ORG_NOT_FOUND` | Organization not found. |
| `HEARTH_ORG_SUSPENDED` | Organization is suspended. |
| `HEARTH_ORG_ALREADY_MEMBER` | User is already a member of this organization. |
| `HEARTH_ORG_NOT_MEMBER` | User is not a member of this organization. |
| `HEARTH_ORG_LAST_OWNER` | Cannot remove the last owner of an organization. |
| `HEARTH_ORG_MEMBER_LIMIT` | Organization has reached its maximum member count. |
| `HEARTH_ORG_DUPLICATE_SLUG` | An organization with this slug already exists. |

### Invitations

| Code | Meaning |
|------|---------|
| `HEARTH_INVITATION_INVALID` | Invitation is invalid, expired, or already used. |
| `HEARTH_INVITATION_DUPLICATE` | An invitation for this email already exists. |

### Self-Service Registration

| Code | Meaning |
|------|---------|
| `HEARTH_REGISTRATION_DISABLED` | Self-service registration is disabled for this realm. |
| `HEARTH_REGISTRATION_DOMAIN_NOT_ALLOWED` | Email domain is not on the realm's allow-list. |
| `HEARTH_REGISTRATION_REQUIRES_INVITATION` | Registration requires a valid invitation token. |

### Passwordless / Magic Link

| Code | Meaning |
|------|---------|
| `HEARTH_MAGIC_LINK_INVALID` | Magic link token is invalid, expired, or already used. |
| `HEARTH_VERIFICATION_TOKEN_INVALID` | Email-verification token is invalid, expired, or already used. |
| `HEARTH_PASSWORD_RESET_TOKEN_INVALID` | Password-reset token is invalid, expired, or already used. |

### Consent

| Code | Meaning |
|------|---------|
| `HEARTH_CONSENT_REQUIRED` | User consent is required before issuing tokens. |
| `HEARTH_CONSENT_TICKET_INVALID` | Consent ticket is invalid or expired. |
| `HEARTH_CONSENT_SCOPE_NOT_REQUESTED` | Approved scope was not in the original authorization request. |
| `HEARTH_CONSENT_NOT_FOUND` | No consent record exists for this client. |

### Federation

| Code | Meaning |
|------|---------|
| `HEARTH_FEDERATION_UNKNOWN_CONNECTOR` | Named federation connector is not registered for this realm. |
| `HEARTH_FEDERATION_INVALID_STATE` | Federation state parameter is invalid or expired. |
| `HEARTH_FEDERATION_UPSTREAM_ERROR` | Upstream IdP returned an error during token exchange or userinfo fetch. |
| `HEARTH_FEDERATION_TOKEN_VERIFICATION_FAILED` | Upstream ID token failed signature or claims verification. |
| `HEARTH_FEDERATION_EMAIL_NOT_VERIFIED` | Upstream IdP returned `email_verified: false`. |
| `HEARTH_FEDERATION_LINK_CONFIRMATION_REQUIRED` | Federation login requires the user to confirm linking an existing account. |
| `HEARTH_FEDERATION_NOT_LINKED` | User has no linked external identity for this connector. |
| `HEARTH_FEDERATION_ALREADY_LINKED` | External identity is already linked (to this or another user). |

### SAML

| Code | Meaning |
|------|---------|
| `HEARTH_SAML_INVALID` | SAML message is invalid (parse, signature, replay, audience, or destination check). |
| `HEARTH_SAML_METADATA_FETCH_FAILED` | Fetching SAML IdP metadata failed. |
| `HEARTH_SAML_ENTITY_NOT_FOUND` | SAML entity (SP or IdP) is not registered for this realm. |

### SCIM

| Code | Meaning |
|------|---------|
| `HEARTH_DUPLICATE_SCIM_EXTERNAL_ID` | SCIM `externalId` is already associated with a different resource. |

### Access Control

| Code | Meaning |
|------|---------|
| `HEARTH_FORBIDDEN` | Caller is not authorized to perform this operation. |
| `HEARTH_SYSTEM_REALM_PROTECTED` | Operation is not permitted on the system realm. |

## Notes

- Error codes are **additive** — new codes are added without breaking existing clients.
- `error_code` is `null` for all 5xx server errors. Clients should treat `null` as an opaque server failure.
- The `error` string is for display purposes only and may change. Always branch on `error_code`.
- Source of truth: [`src/protocol/error_codes.rs`](../../src/protocol/error_codes.rs).
