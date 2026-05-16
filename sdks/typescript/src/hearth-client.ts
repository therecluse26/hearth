import { ConfigurationError, DiscoveryError } from "./errors.js";
import { JwksClient } from "./jwks-client.js";
import { IntrospectionClient } from "./introspection-client.js";

/** Configuration for {@link HearthClient}. */
export interface HearthClientConfig {
  /**
   * Root URL of the Hearth instance, e.g. `https://auth.example.com`.
   * Required. Must be a valid HTTPS URL.
   */
  issuerUrl: string;
  /**
   * OAuth 2.0 client ID.
   * Required for flows that need a client identity (e.g. introspection).
   */
  clientId?: string;
  /**
   * OAuth 2.0 client secret.
   * Required for confidential client flows (e.g. introspection).
   */
  clientSecret?: string;
  /**
   * Override JWKS cache TTL in milliseconds.
   * Default: respect `Cache-Control: max-age` from the JWKS endpoint,
   * falling back to 5 minutes.
   */
  jwksTtl?: number;
  /**
   * Override the introspection endpoint URL discovered via OIDC discovery.
   * When absent, the URL is taken from `introspection_endpoint` in the
   * OIDC discovery document.
   */
  introspectionEndpoint?: string;
  /**
   * Timeout for all outbound HTTP calls in milliseconds.
   * Default: 10 000 (10 seconds).
   */
  httpTimeout?: number;
}

interface OidcConfiguration {
  issuer: string;
  jwks_uri: string;
  introspection_endpoint?: string;
  [key: string]: unknown;
}

/**
 * Primary entry point for the Hearth Node.js SDK.
 *
 * Accepts a single configuration object, auto-discovers all endpoint URLs
 * from `{issuerUrl}/.well-known/openid-configuration` on first use, and
 * applies `httpTimeout` to every outbound fetch call.
 *
 * Lower-level access is available via {@link JwksClient} and
 * {@link IntrospectionClient}.
 */
export class HearthClient {
  /** Issuer URL, trailing slash removed. */
  readonly issuerUrl: string;
  readonly clientId: string | undefined;
  readonly clientSecret: string | undefined;
  readonly jwksTtl: number | undefined;
  readonly introspectionEndpointOverride: string | undefined;
  /** HTTP timeout in milliseconds applied to all outbound fetch calls. */
  readonly httpTimeout: number;

  private _discovery: OidcConfiguration | null = null;
  private _jwksClient: JwksClient | null = null;
  private _introspectionClient: IntrospectionClient | null = null;

  constructor(config: HearthClientConfig) {
    if (!config.issuerUrl) {
      throw new ConfigurationError("issuerUrl is required");
    }
    try {
      new URL(config.issuerUrl);
    } catch {
      throw new ConfigurationError(
        `issuerUrl "${config.issuerUrl}" is not a valid URL`,
      );
    }

    this.issuerUrl = config.issuerUrl.replace(/\/$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.jwksTtl = config.jwksTtl;
    this.introspectionEndpointOverride = config.introspectionEndpoint;
    this.httpTimeout = config.httpTimeout ?? 10_000;
  }

  /**
   * Fetches and caches the OIDC discovery document from
   * `{issuerUrl}/.well-known/openid-configuration`.
   *
   * Throws {@link DiscoveryError} when the endpoint is unreachable,
   * returns a non-2xx status, or returns invalid JSON.
   */
  async discover(): Promise<OidcConfiguration> {
    if (this._discovery) return this._discovery;

    const url = `${this.issuerUrl}/.well-known/openid-configuration`;
    let resp: Response;
    try {
      resp = await fetch(url, {
        signal: AbortSignal.timeout(this.httpTimeout),
      });
    } catch (err) {
      throw new DiscoveryError(
        `OIDC discovery endpoint unreachable: ${url}`,
        { cause: err },
      );
    }

    if (!resp.ok) {
      throw new DiscoveryError(
        `OIDC discovery returned HTTP ${resp.status}`,
      );
    }

    let doc: OidcConfiguration;
    try {
      doc = (await resp.json()) as OidcConfiguration;
    } catch (err) {
      throw new DiscoveryError(`OIDC discovery returned invalid JSON`, {
        cause: err,
      });
    }

    if (!doc.jwks_uri) {
      throw new DiscoveryError(
        "OIDC discovery document is missing required field: jwks_uri",
      );
    }

    this._discovery = doc;
    return doc;
  }

  /**
   * Returns a {@link JwksClient} bound to the `jwks_uri` discovered from
   * the OIDC configuration. The client is created once and reused.
   */
  async jwksClient(): Promise<JwksClient> {
    if (this._jwksClient) return this._jwksClient;
    const doc = await this.discover();
    this._jwksClient = new JwksClient({
      jwksUri: doc.jwks_uri,
      ttl: this.jwksTtl,
      httpTimeout: this.httpTimeout,
    });
    return this._jwksClient;
  }

  /**
   * Returns an {@link IntrospectionClient} bound to the introspection
   * endpoint. The endpoint is taken from `introspectionEndpoint` config
   * (if provided) or from the OIDC discovery document.
   *
   * Throws {@link ConfigurationError} when:
   * - `clientId` or `clientSecret` are absent (required for introspection)
   * - No introspection endpoint is configured or discoverable
   */
  async introspectionClient(): Promise<IntrospectionClient> {
    if (this._introspectionClient) return this._introspectionClient;

    if (!this.clientId || !this.clientSecret) {
      throw new ConfigurationError(
        "clientId and clientSecret are required for token introspection",
      );
    }

    const endpoint =
      this.introspectionEndpointOverride ??
      (await this.discover()).introspection_endpoint;

    if (!endpoint) {
      throw new ConfigurationError(
        "introspection_endpoint is not present in the OIDC discovery document " +
          "and no introspectionEndpoint override was provided in config",
      );
    }

    this._introspectionClient = new IntrospectionClient({
      introspectionEndpoint: endpoint,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      httpTimeout: this.httpTimeout,
    });
    return this._introspectionClient;
  }
}
