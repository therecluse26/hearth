/**
 * Spec §5 — Hearth SDK error hierarchy.
 *
 * All SDK-specific errors extend HearthSdkError so callers can catch
 * the entire category with a single `instanceof HearthSdkError` check.
 */

/** Base class for all Hearth SDK errors. */
export class HearthSdkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/** Thrown when the client is misconfigured (missing baseUrl, realmId, etc.). */
export class ConfigurationError extends HearthSdkError {
  constructor(message: string) {
    super(message);
  }
}

/** Thrown when the OIDC discovery document cannot be fetched or parsed. */
export class DiscoveryError extends HearthSdkError {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
  }
}

/** Thrown when fetching or parsing the JWKS document fails. */
export class JWKSFetchError extends HearthSdkError {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
  }
}

/** Thrown when a token's `exp` claim is in the past. */
export class TokenExpiredError extends HearthSdkError {
  constructor(
    public readonly expiredAt: Date,
    message = `Token expired at ${expiredAt.toISOString()}`,
  ) {
    super(message);
  }
}

/** Thrown when a token's `nbf` claim is in the future. */
export class TokenNotYetValidError extends HearthSdkError {
  constructor(
    public readonly notBefore: Date,
    message = `Token not yet valid until ${notBefore.toISOString()}`,
  ) {
    super(message);
  }
}

/** Thrown when a token fails signature or structural validation. */
export class TokenInvalidError extends HearthSdkError {
  constructor(message: string) {
    super(message);
  }
}

/** Thrown when the token's `iss` claim does not match the expected issuer. */
export class TokenIssuerError extends HearthSdkError {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
    message = `Token issuer mismatch: expected "${expected}", got "${actual}"`,
  ) {
    super(message);
  }
}

/** Thrown when the token's `aud` claim does not include the expected audience. */
export class TokenAudienceError extends HearthSdkError {
  constructor(
    public readonly expected: string,
    public readonly actual: string[],
    message = `Token audience mismatch: expected "${expected}", got [${actual.join(", ")}]`,
  ) {
    super(message);
  }
}

/** Thrown when a token introspection request fails or returns inactive. */
export class IntrospectionError extends HearthSdkError {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
  }
}
