import { decodeJwt } from "jose";
import { HearthApiClient } from "./client.js";
import type { MePermissionsResponse } from "./types.js";

/** Options for creating a {@link HearthClient} facade. */
export interface HearthOptions {
  /** Base URL of the Hearth server, e.g. `https://hearth.example.com`. */
  baseUrl: string;
  /** Realm ID to scope all requests to. */
  realmId: string;
  /**
   * Called synchronously on every `hasPermission` / `hasRole` /
   * `inGroup` / `inOrg` check. Return `null`/`undefined` when the
   * caller is unauthenticated.
   */
  getToken: () => string | null | undefined;
}

/**
 * Minimum HTTP surface exposed by the facade.
 *
 * For the full API (auth code flow, admin, JWKS, etc.) construct a
 * {@link HearthClient} directly.
 */
export interface HearthHttpClient {
  /**
   * Calls `GET /v1/me/permissions` and returns the freshly-resolved
   * RBAC claim set for the current bearer token.
   */
  permissions(): Promise<MePermissionsResponse>;
}

/**
 * RBAC claim-oriented facade over {@link HearthClient}.
 *
 * All boolean predicates are synchronous, lock-free, and decode the JWT
 * returned by `getToken()` on every call. No network traffic, no cache.
 * When the token is absent or malformed, every predicate returns `false`.
 */
export interface HearthFacade {
  /**
   * Returns `true` iff the JWT `permissions` claim contains `permission`.
   */
  hasPermission(permission: string): boolean;
  /**
   * Returns `true` iff the JWT `roles` claim contains `role`.
   */
  hasRole(role: string): boolean;
  /**
   * Returns `true` iff the JWT `groups` claim contains `group`.
   */
  inGroup(group: string): boolean;
  /**
   * Returns `true` iff the JWT `oid` claim equals `org`.
   */
  inOrg(org: string): boolean;
  /** Narrow HTTP surface for live RBAC resolution. */
  client: HearthHttpClient;
}

interface RbacJwtClaims {
  permissions?: unknown;
  roles?: unknown;
  groups?: unknown;
  oid?: unknown;
}

/**
 * Decode the middle JWT segment using `jose.decodeJwt`. Returns `null`
 * when the token is missing, malformed, or cannot be parsed as JSON.
 * Signature is NOT verified — the app trusts its own token.
 */
function safeDecode(token: string | null | undefined): RbacJwtClaims | null {
  if (!token || typeof token !== "string") {
    return null;
  }
  try {
    return decodeJwt(token) as RbacJwtClaims;
  } catch {
    return null;
  }
}

function arrayContains(claim: unknown, value: string): boolean {
  return Array.isArray(claim) && claim.includes(value);
}

/**
 * Create a {@link HearthFacade} over the RBAC claim set embedded in the
 * JWT returned by `opts.getToken()`.
 */
export function createHearth(opts: HearthOptions): HearthFacade {
  const http = new HearthApiClient({
    baseUrl: opts.baseUrl,
    realmId: opts.realmId,
  });

  function claims(): RbacJwtClaims | null {
    return safeDecode(opts.getToken());
  }

  return {
    hasPermission(permission: string): boolean {
      const c = claims();
      return c !== null && arrayContains(c.permissions, permission);
    },
    hasRole(role: string): boolean {
      const c = claims();
      return c !== null && arrayContains(c.roles, role);
    },
    inGroup(group: string): boolean {
      const c = claims();
      return c !== null && arrayContains(c.groups, group);
    },
    inOrg(org: string): boolean {
      const c = claims();
      return c !== null && typeof c.oid === "string" && c.oid === org;
    },
    client: {
      permissions(): Promise<MePermissionsResponse> {
        const token = opts.getToken();
        if (!token) {
          return Promise.reject(
            new Error("getToken() returned no token; cannot call permissions()"),
          );
        }
        return http.permissions(token);
      },
    },
  };
}
