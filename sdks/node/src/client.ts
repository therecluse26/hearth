/** §1 — HearthClient: unified entry point for the @hearth/node SDK. */

import type { HearthConfig } from "./config.js";
import { resolveConfig } from "./config.js";
import { DiscoveryClient } from "./discovery.js";
import { JwksVerifier } from "./jwks.js";
import { IntrospectionClient } from "./introspect.js";
import type { IntrospectionResult } from "./introspect.js";
import type { VerifiedToken } from "./token.js";

export class HearthClient {
  private readonly verifier: JwksVerifier;
  private readonly introspectionClient: IntrospectionClient;
  private readonly discovery: DiscoveryClient;

  constructor(config: HearthConfig) {
    const resolved = resolveConfig(config);
    this.discovery = new DiscoveryClient(resolved.issuer_url, resolved.http_timeout);
    this.verifier = new JwksVerifier(resolved, this.discovery);
    this.introspectionClient = new IntrospectionClient(resolved, () => this.discovery.discover());
  }

  /**
   * Verify a JWT using JWKS.
   * Supports RS256 and ES256. Validates exp, iss, aud, iat (with clock skew tolerance).
   * On key miss, re-fetches the JWKS once before failing (handles key rotation).
   */
  async verifyToken(token: string): Promise<VerifiedToken> {
    return this.verifier.verifyToken(token);
  }

  /**
   * Introspect a token per RFC 7662.
   * Returns IntrospectionResult with active, sub, iss, aud, exp, iat, scope, extra.
   */
  async introspect(token: string, tokenTypeHint?: "access_token" | "refresh_token"): Promise<IntrospectionResult> {
    return this.introspectionClient.introspect(token, tokenTypeHint);
  }

  /**
   * Force eviction of the JWKS and discovery caches.
   * Call this after receiving a 401 from a resource server protected by the same issuer.
   */
  invalidateCache(): void {
    this.verifier.invalidateCache();
  }
}
