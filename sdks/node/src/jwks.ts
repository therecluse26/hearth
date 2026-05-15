/** §2 — JWKS-backed token verification with cache-control, background refresh, and 401 re-fetch. */

import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import type { JWTVerifyOptions, RemoteJWKSetOptions, JWSHeaderParameters, FlattenedJWSInput, GetKeyFunction } from "jose";
import { DiscoveryClient } from "./discovery.js";
import { JwksFetchError, TokenVerificationError, TokenExpiredError, TokenClaimsError } from "./errors.js";
import { VerifiedToken } from "./token.js";
import type { ResolvedConfig } from "./config.js";

/** Key resolver type — the common base accepted by jwtVerify. */
type JwkKeyArg = GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>;

/** Testability hook: override how the JWK set is built (e.g. use createLocalJWKSet in tests). */
export type JwkSetFactory = (jwksUri: string, ttlMs: number) => JwkKeyArg;

export class JwksVerifier {
  private readonly discovery: DiscoveryClient;
  private remoteJwkSet: JwkKeyArg | null = null;
  private readonly config: ResolvedConfig;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly jwkSetFactory: JwkSetFactory;

  constructor(config: ResolvedConfig, discovery?: DiscoveryClient, jwkSetFactory?: JwkSetFactory) {
    this.config = config;
    this.discovery = discovery ?? new DiscoveryClient(config.issuer_url, config.http_timeout);
    this.jwkSetFactory = jwkSetFactory ?? ((uri, ttl) =>
      createRemoteJWKSet(new URL(uri), { cacheMaxAge: ttl, cooldownDuration: 30_000 } as RemoteJWKSetOptions) as unknown as JwkKeyArg
    );
  }

  private async buildJwkSet(): Promise<JwkKeyArg> {
    let jwksUri: string;
    try {
      const doc = await this.discovery.discover();
      jwksUri = doc.jwks_uri;
    } catch (err) {
      if (err instanceof JwksFetchError) throw err;
      throw new JwksFetchError("Failed to discover JWKS URI", { cause: err });
    }

    const cacheMaxAge = Math.min(this.config.jwks_ttl, 24 * 60 * 60 * 1000);
    const jwkSet = this.jwkSetFactory(jwksUri, cacheMaxAge);
    this.scheduleBackgroundRefresh(cacheMaxAge);
    return jwkSet;
  }

  private scheduleBackgroundRefresh(ttlMs: number): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    // Background refresh at 80% of TTL to warm cache before expiry
    const delay = Math.max(ttlMs * 0.8, 60_000);
    this.refreshTimer = setTimeout(() => {
      this.remoteJwkSet = null;
      // Fire-and-forget: re-prime the JWK set; errors are silently swallowed
      // to avoid crashing background timers. The next verify() call will retry.
      this.getJwkSet().catch(() => undefined);
    }, delay);
    // Don't block process exit
    if (this.refreshTimer.unref) this.refreshTimer.unref();
  }

  private async getJwkSet(): Promise<JwkKeyArg> {
    if (!this.remoteJwkSet) {
      this.remoteJwkSet = await this.buildJwkSet();
    }
    return this.remoteJwkSet;
  }

  /** Verify a JWT using the JWKS endpoint. Supports RS256 and ES256. */
  async verifyToken(token: string): Promise<VerifiedToken> {
    const jwkSet = await this.getJwkSet();

    const verifyOptions: JWTVerifyOptions = {
      issuer: this.config.issuer_url,
      clockTolerance: this.config.clock_skew_seconds,
      algorithms: ["RS256", "ES256", "RS384", "ES384", "RS512", "ES512", "EdDSA"],
    };
    if (this.config.audience.length > 0) {
      verifyOptions.audience = this.config.audience;
    }

    try {
      const result = await jwtVerify(token, jwkSet, verifyOptions);
      return new VerifiedToken(result.payload, result.protectedHeader as Record<string, unknown>);
    } catch (err) {
      if (err instanceof joseErrors.JWTExpired) {
        const expiredAt = err.payload?.exp ? new Date(err.payload.exp * 1000) : new Date(0);
        throw new TokenExpiredError(expiredAt, { cause: err });
      }
      if (
        err instanceof joseErrors.JWKSNoMatchingKey ||
        err instanceof joseErrors.JWKSMultipleMatchingKeys
      ) {
        // JWKS key not found — re-fetch once and retry (handles key rotation / 401-like scenario)
        this.remoteJwkSet = null;
        const freshSet = await this.getJwkSet().catch((e) => {
          throw new JwksFetchError("JWKS re-fetch after key miss failed", { cause: e });
        });
        try {
          const result = await jwtVerify(token, freshSet, verifyOptions);
          return new VerifiedToken(result.payload, result.protectedHeader as Record<string, unknown>);
        } catch (retryErr) {
          throw new TokenVerificationError("Token verification failed after JWKS refresh", { cause: retryErr });
        }
      }
      if (
        err instanceof joseErrors.JWTClaimValidationFailed ||
        err instanceof joseErrors.JWTInvalid
      ) {
        throw new TokenClaimsError(
          `Token claim validation failed: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
      throw new TokenVerificationError(
        `Token verification failed: ${err instanceof Error ? err.message : "unknown error"}`,
        { cause: err },
      );
    }
  }

  /** Force JWKS cache eviction (e.g. on receiving a 401 from a resource server). */
  invalidateCache(): void {
    this.remoteJwkSet = null;
    this.discovery.reset();
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
}
