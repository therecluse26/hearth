/** §4 — VerifiedToken: typed claims accessors and helpers. */

import { timingSafeEqual } from "node:crypto";
import type { JWTPayload } from "jose";

function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a.padEnd(Math.max(a.length, b.length), "\0"));
  const bufB = Buffer.from(b.padEnd(Math.max(a.length, b.length), "\0"));
  return timingSafeEqual(bufA, bufB);
}

interface RawPayload extends JWTPayload {
  scope?: string;
  scopes?: string[];
  roles?: string[];
  permissions?: string[];
  [key: string]: unknown;
}

export class VerifiedToken {
  private readonly _payload: RawPayload;
  private readonly _header: Record<string, unknown>;

  constructor(payload: JWTPayload, header: Record<string, unknown>) {
    this._payload = payload as RawPayload;
    this._header = header;
  }

  /** The `sub` claim. Returns empty string if absent. */
  subject(): string {
    return this._payload.sub ?? "";
  }

  /** The `iss` claim. Returns empty string if absent. */
  issuer(): string {
    return this._payload.iss ?? "";
  }

  /** The `aud` claim normalized to an array. */
  audience(): string[] {
    const aud = this._payload.aud;
    if (!aud) return [];
    return Array.isArray(aud) ? aud : [aud];
  }

  /** The `iat` claim as a Date, or null if absent. */
  issuedAt(): Date | null {
    return this._payload.iat !== undefined ? new Date(this._payload.iat * 1000) : null;
  }

  /** The `exp` claim as a Date, or null if absent. */
  expiresAt(): Date | null {
    return this._payload.exp !== undefined ? new Date(this._payload.exp * 1000) : null;
  }

  /** The `nbf` claim as a Date, or null if absent. */
  notBefore(): Date | null {
    return this._payload.nbf !== undefined ? new Date(this._payload.nbf * 1000) : null;
  }

  /** The raw `scope` string claim (space-separated). Returns empty string if absent. */
  scope(): string {
    return this._payload.scope ?? "";
  }

  /** The `scope` claim split into individual values, or the `scopes` array if present. */
  scopes(): string[] {
    if (this._payload.scopes) return [...this._payload.scopes];
    const sc = this._payload.scope;
    if (!sc) return [];
    return sc.split(/\s+/).filter(Boolean);
  }

  /** Get an arbitrary claim by key. */
  get(key: string): unknown {
    return this._payload[key];
  }

  /** Return the raw JWT payload object. */
  raw(): Readonly<RawPayload> {
    return Object.freeze({ ...this._payload });
  }

  /** Timing-safe check: returns true if the token contains the given scope. */
  hasScope(s: string): boolean {
    return this.scopes().some((sc) => timingSafeStringEqual(sc, s));
  }

  /** Timing-safe check: returns true if the token's `roles` claim contains the given role. */
  hasRole(r: string): boolean {
    return (this._payload.roles ?? []).some((role) => timingSafeStringEqual(role, r));
  }

  /** Timing-safe check: returns true if the token's `permissions` claim contains the given permission. */
  hasPermission(p: string): boolean {
    return (this._payload.permissions ?? []).some((perm) => timingSafeStringEqual(perm, p));
  }
}
