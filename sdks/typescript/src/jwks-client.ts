import type { JsonWebKey } from "./types.js";

/** Configuration for {@link JwksClient}. */
export interface JwksClientConfig {
  /** URL of the JWKS endpoint (e.g. from OIDC discovery `jwks_uri`). */
  jwksUri: string;
  /**
   * Override cache TTL in milliseconds.
   * When absent, the client respects `Cache-Control: max-age` from the JWKS
   * response and falls back to 5 minutes.
   */
  ttl?: number;
  /** Timeout for outbound HTTP calls in milliseconds. Default: 10 000. */
  httpTimeout?: number;
}

/**
 * Low-level JWKS fetcher.
 *
 * Fetches the JSON Web Key Set from the configured endpoint.
 * Full caching and rotation logic will be added in §2.
 */
export class JwksClient {
  private readonly jwksUri: string;
  readonly ttl: number | undefined;
  readonly httpTimeout: number;

  constructor(config: JwksClientConfig) {
    this.jwksUri = config.jwksUri;
    this.ttl = config.ttl;
    this.httpTimeout = config.httpTimeout ?? 10_000;
  }

  /** Fetch the current JWKS keys from the endpoint. */
  async fetchKeys(): Promise<JsonWebKey[]> {
    const resp = await fetch(this.jwksUri, {
      signal: AbortSignal.timeout(this.httpTimeout),
    });
    if (!resp.ok) {
      throw new Error(`JWKS fetch failed with HTTP ${resp.status}`);
    }
    const doc = (await resp.json()) as { keys: JsonWebKey[] };
    return doc.keys;
  }
}
