/** RFC 7662 §2.2 — result of a token introspection request. */
export interface IntrospectionResult {
  /** Whether the token is currently active. */
  active: boolean;
  /** Subject identifier (when active). */
  sub?: string;
  /** Expiration time as Unix seconds (when active). */
  exp?: number;
  /** Issued-at time as Unix seconds (when active). */
  iat?: number;
  /** Issuer identifier (when active). */
  iss?: string;
  /** Intended audience (when active). */
  aud?: string | string[];
  /** Space-separated scope string (when active and present). */
  scope?: string;
  /** OAuth client that requested the token (when active and present). */
  client_id?: string;
  /** All non-standard claims. */
  [key: string]: unknown;
}

/** Configuration for {@link IntrospectionClient}. */
export interface IntrospectionClientConfig {
  /** RFC 7662 introspection endpoint URL. */
  introspectionEndpoint: string;
  /** Client ID used for HTTP Basic authentication. */
  clientId: string;
  /** Client secret used for HTTP Basic authentication. */
  clientSecret: string;
  /** Timeout for outbound HTTP calls in milliseconds. Default: 10 000. */
  httpTimeout?: number;
}

/**
 * Low-level RFC 7662 token introspection client.
 *
 * Results are never cached — per RFC 7662 §2.1, token state can change
 * at any time. Full error taxonomy will be added in §3.
 */
export class IntrospectionClient {
  private readonly endpoint: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  readonly httpTimeout: number;

  constructor(config: IntrospectionClientConfig) {
    this.endpoint = config.introspectionEndpoint;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.httpTimeout = config.httpTimeout ?? 10_000;
  }

  /** Introspect a token. Never cached per RFC 7662 §2.1. */
  async introspect(token: string): Promise<IntrospectionResult> {
    const credentials = btoa(`${this.clientId}:${this.clientSecret}`);
    const resp = await fetch(this.endpoint, {
      method: "POST",
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token }),
      signal: AbortSignal.timeout(this.httpTimeout),
    });
    if (!resp.ok) {
      throw new Error(`Introspection endpoint returned HTTP ${resp.status}`);
    }
    return resp.json() as Promise<IntrospectionResult>;
  }
}
