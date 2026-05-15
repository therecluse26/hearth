/**
 * Thrown when the client is constructed with missing required config or an
 * invalid issuer URL. This is a programmer error — check config at startup.
 */
export class ConfigurationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ConfigurationError";
  }
}

/**
 * Thrown when the OIDC discovery endpoint is unreachable or returns an
 * invalid response. Wraps the underlying network or parse error via `cause`.
 */
export class DiscoveryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DiscoveryError";
  }
}
