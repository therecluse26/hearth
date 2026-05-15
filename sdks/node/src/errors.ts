/** §5 — Hearth Node SDK error taxonomy. */

const REDACTED = "[redacted]";

function sanitize(value: string): string {
  // Redact anything that looks like a JWT (three base64url segments)
  return value.replace(/[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g, REDACTED);
}

/** Base class for all @hearth/node errors. Messages are sanitized to remove tokens/secrets. */
export class HearthError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(sanitize(message), options);
    this.name = this.constructor.name;
    if (Error.captureStackTrace) Error.captureStackTrace(this, this.constructor);
  }
}

/** Thrown when the HearthClient is misconfigured (missing required fields, invalid URLs). */
export class ConfigurationError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when OIDC discovery (/.well-known/openid-configuration) fails. */
export class DiscoveryError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when fetching or parsing the JWKS document fails. */
export class JwksFetchError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when token signature verification fails or the token is structurally invalid. */
export class TokenVerificationError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when token `exp` claim is in the past (beyond clock skew tolerance). */
export class TokenExpiredError extends TokenVerificationError {
  constructor(expiredAt: Date, options?: { cause?: unknown }) {
    super(`Token expired at ${expiredAt.toISOString()}`, options);
  }
}

/** Thrown when a required claim is missing, wrong type, or fails validation (iss, aud, iat). */
export class TokenClaimsError extends TokenVerificationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when the introspection request fails or returns an unexpected response. */
export class IntrospectionError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown by Express/Fastify middleware when configuration is invalid or setup fails. */
export class MiddlewareError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}
