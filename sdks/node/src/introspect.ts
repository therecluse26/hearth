/** §3 — Token introspection per RFC 7662. */

import { IntrospectionError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";
import type { OidcDiscovery } from "./discovery.js";

/** RFC 7662 introspection response — required fields per spec §3. */
export interface IntrospectionResult {
  active: boolean;
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  scope?: string;
  /** Catch-all for non-standard claims returned by the server. */
  extra: Record<string, unknown>;
}

export class IntrospectionClient {
  private readonly credentials: string;

  constructor(
    private readonly config: ResolvedConfig,
    private readonly getDiscovery: () => Promise<OidcDiscovery>,
  ) {
    this.credentials = Buffer.from(
      `${config.client_id}:${config.client_secret}`,
    ).toString("base64");
  }

  private async getIntrospectionEndpoint(): Promise<string> {
    if (this.config.introspection_endpoint) return this.config.introspection_endpoint;
    const doc = await this.getDiscovery();
    if (!doc.introspection_endpoint) {
      throw new IntrospectionError(
        "Introspection endpoint not found in OIDC discovery document and no override configured",
      );
    }
    return doc.introspection_endpoint;
  }

  /** Introspect a token per RFC 7662. */
  async introspect(token: string, tokenTypeHint?: "access_token" | "refresh_token"): Promise<IntrospectionResult> {
    const endpoint = await this.getIntrospectionEndpoint();

    const body = new URLSearchParams({ token });
    if (tokenTypeHint) body.set("token_type_hint", tokenTypeHint);

    let res: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.http_timeout);
      res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${this.credentials}`,
        },
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      throw new IntrospectionError("Introspection request failed", { cause: err });
    }

    if (!res.ok) {
      throw new IntrospectionError(`Introspection endpoint returned HTTP ${res.status}`);
    }

    let raw: Record<string, unknown>;
    try {
      raw = await res.json() as Record<string, unknown>;
    } catch (err) {
      throw new IntrospectionError("Introspection response is not valid JSON", { cause: err });
    }

    const { active, sub, iss, aud, exp, iat, scope, ...rest } = raw;
    return {
      active: Boolean(active),
      sub: typeof sub === "string" ? sub : undefined,
      iss: typeof iss === "string" ? iss : undefined,
      aud: typeof aud === "string" || Array.isArray(aud) ? aud as string | string[] : undefined,
      exp: typeof exp === "number" ? exp : undefined,
      iat: typeof iat === "number" ? iat : undefined,
      scope: typeof scope === "string" ? scope : undefined,
      extra: rest,
    };
  }
}
