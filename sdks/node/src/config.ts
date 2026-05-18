/** §1 — HearthConfig: spec-compliant configuration for HearthClient. */

import { ConfigurationError } from "./errors.js";

export interface HearthConfig {
  /** OIDC issuer URL. JWKS and introspection endpoints are auto-discovered from here. */
  issuer_url: string;
  /** OAuth2 client ID used for introspection. */
  client_id: string;
  /** OAuth2 client secret used for introspection. */
  client_secret: string;
  /** Optional accepted audience (string or array). Omit to skip audience validation. */
  audience?: string | string[];
  /** JWKS cache TTL in milliseconds. Defaults to 5 minutes; hard cap 24 hours. */
  jwks_ttl?: number;
  /** Override introspection endpoint URL (auto-discovered if omitted). */
  introspection_endpoint?: string;
  /** HTTP request timeout in milliseconds. Default: 10 000. */
  http_timeout?: number;
  /** Clock skew tolerance in seconds for exp/iat validation. Default: 60. */
  clock_skew_seconds?: number;
}

export const JWKS_TTL_DEFAULT_MS = 5 * 60 * 1000;    // 5 min
export const JWKS_TTL_MAX_MS = 24 * 60 * 60 * 1000;  // 24 h
export const HTTP_TIMEOUT_DEFAULT_MS = 10_000;
export const CLOCK_SKEW_DEFAULT_S = 60;

export interface ResolvedConfig {
  issuer_url: string;
  client_id: string;
  client_secret: string;
  audience: string[];
  jwks_ttl: number;
  introspection_endpoint: string | null;
  http_timeout: number;
  clock_skew_seconds: number;
}

export function resolveConfig(config: HearthConfig): ResolvedConfig {
  if (!config.issuer_url) throw new ConfigurationError("issuer_url is required");
  if (!config.client_id) throw new ConfigurationError("client_id is required");
  if (!config.client_secret) throw new ConfigurationError("client_secret is required");

  let jwks_ttl = config.jwks_ttl ?? JWKS_TTL_DEFAULT_MS;
  if (jwks_ttl > JWKS_TTL_MAX_MS) jwks_ttl = JWKS_TTL_MAX_MS;

  const audience = config.audience
    ? Array.isArray(config.audience) ? config.audience : [config.audience]
    : [];

  return {
    issuer_url: config.issuer_url.replace(/\/$/, ""),
    client_id: config.client_id,
    client_secret: config.client_secret,
    audience,
    jwks_ttl,
    introspection_endpoint: config.introspection_endpoint ?? null,
    http_timeout: config.http_timeout ?? HTTP_TIMEOUT_DEFAULT_MS,
    clock_skew_seconds: config.clock_skew_seconds ?? CLOCK_SKEW_DEFAULT_S,
  };
}
