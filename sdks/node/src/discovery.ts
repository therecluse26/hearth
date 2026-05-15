/** §1 — OIDC auto-discovery from {issuer_url}/.well-known/openid-configuration */

import { DiscoveryError } from "./errors.js";

export interface OidcDiscovery {
  issuer: string;
  jwks_uri: string;
  introspection_endpoint?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  [key: string]: unknown;
}

export class DiscoveryClient {
  private cache: OidcDiscovery | null = null;
  private fetchPromise: Promise<OidcDiscovery> | null = null;

  constructor(
    private readonly issuerUrl: string,
    private readonly httpTimeout: number,
  ) {}

  async discover(): Promise<OidcDiscovery> {
    if (this.cache) return this.cache;
    // Deduplicate concurrent calls
    if (!this.fetchPromise) {
      this.fetchPromise = this.fetchDiscovery().then((doc) => {
        this.cache = doc;
        this.fetchPromise = null;
        return doc;
      }).catch((err) => {
        this.fetchPromise = null;
        throw err;
      });
    }
    return this.fetchPromise;
  }

  private async fetchDiscovery(): Promise<OidcDiscovery> {
    const url = `${this.issuerUrl}/.well-known/openid-configuration`;
    let res: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.httpTimeout);
      res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
    } catch (err) {
      throw new DiscoveryError(`OIDC discovery fetch failed: ${url}`, { cause: err });
    }
    if (!res.ok) {
      throw new DiscoveryError(`OIDC discovery returned HTTP ${res.status}: ${url}`);
    }
    let doc: OidcDiscovery;
    try {
      doc = await res.json() as OidcDiscovery;
    } catch (err) {
      throw new DiscoveryError("OIDC discovery response is not valid JSON", { cause: err });
    }
    if (!doc.jwks_uri) {
      throw new DiscoveryError("OIDC discovery document missing required field: jwks_uri");
    }
    return doc;
  }

  /** Reset cached discovery document (e.g. for testing or after key rotation). */
  reset(): void {
    this.cache = null;
  }
}
