/**
 * Spec §4 — Claims API.
 *
 * {@link Claims} wraps a decoded JWT payload and exposes typed accessors
 * for standard OIDC and Hearth-specific claims.  All reads are local —
 * no network call is made.  Signature verification is the caller's
 * responsibility (e.g. via the JWKS endpoint before constructing Claims).
 */

import { decodeJwt } from "jose";
import {
  TokenExpiredError,
  TokenInvalidError,
  TokenNotYetValidError,
} from "./errors.js";

/** Raw JWT payload shape used internally. */
interface RawPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  scope?: string;
  scopes?: string[];
  roles?: string[];
  permissions?: string[];
  [key: string]: unknown;
}

/**
 * Typed accessor for a decoded JWT's claims.
 *
 * Construct via {@link Claims.decode} (decodes without verifying signature)
 * or pass a pre-decoded payload to the constructor.
 */
export class Claims {
  private readonly payload: RawPayload;

  constructor(payload: RawPayload) {
    this.payload = payload;
  }

  /**
   * Decode a JWT string into a {@link Claims} object.
   * The signature is NOT verified — the caller must verify it separately.
   *
   * @throws {TokenInvalidError} if the string is not a valid JWT.
   */
  static decode(token: string): Claims {
    try {
      const payload = decodeJwt(token) as RawPayload;
      return new Claims(payload);
    } catch (err) {
      throw new TokenInvalidError(
        `Failed to decode JWT: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /**
   * Assert the token is temporally valid (not expired, past nbf).
   *
   * @throws {TokenExpiredError} if exp is in the past.
   * @throws {TokenNotYetValidError} if nbf is in the future.
   */
  assertValid(clockSkewSeconds = 0): void {
    const now = Math.floor(Date.now() / 1000);
    const exp = this.payload.exp;
    if (exp !== undefined && now > exp + clockSkewSeconds) {
      throw new TokenExpiredError(new Date(exp * 1000));
    }
    const nbf = this.payload.nbf;
    if (nbf !== undefined && now < nbf - clockSkewSeconds) {
      throw new TokenNotYetValidError(new Date(nbf * 1000));
    }
  }

  /** The `sub` (subject) claim — identifies the principal that is the subject of the JWT. */
  subject(): string {
    return this.payload.sub ?? "";
  }

  /** The `iss` (issuer) claim — identifies the principal that issued the JWT. */
  issuer(): string {
    return this.payload.iss ?? "";
  }

  /** The `aud` (audiences) claim — normalized to an array. */
  audiences(): string[] {
    const aud = this.payload.aud;
    if (!aud) return [];
    return Array.isArray(aud) ? aud : [aud];
  }

  /** The `exp` (expiry) claim as a Date, or null if absent. */
  expiry(): Date | null {
    return this.payload.exp !== undefined
      ? new Date(this.payload.exp * 1000)
      : null;
  }

  /** The `iat` (issuedAt) claim as a Date, or null if absent. */
  issuedAt(): Date | null {
    return this.payload.iat !== undefined
      ? new Date(this.payload.iat * 1000)
      : null;
  }

  /** The `jti` (JWT ID) claim, or null if absent. */
  jwtID(): string | null {
    return this.payload.jti ?? null;
  }

  /** The `scope` claim split into individual scopes (or `scopes` array if present). */
  scopes(): string[] {
    if (this.payload.scopes) return this.payload.scopes;
    const scope = this.payload.scope;
    if (!scope) return [];
    return scope.split(/\s+/).filter(Boolean);
  }

  /** Returns true iff the token contains the given scope. */
  hasScope(scope: string): boolean {
    return this.scopes().includes(scope);
  }

  /** Returns true iff the token's `roles` claim contains the given role. */
  hasRole(role: string): boolean {
    return (this.payload.roles ?? []).includes(role);
  }

  /** Returns true iff the token's `permissions` claim contains the given permission. */
  hasPermission(permission: string): boolean {
    return (this.payload.permissions ?? []).includes(permission);
  }

  /** Access an arbitrary claim by key. */
  get(key: string): unknown {
    return this.payload[key];
  }
}
