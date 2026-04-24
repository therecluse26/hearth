import type {
  AuthorizeParams,
  AuthorizeResponse,
  BootstrapResponse,
  CapabilityBundle,
  CheckRequestItem,
  CheckResponse,
  JwksDocument,
  RegisterClientParams,
  OAuthClient,
  TokenExchangeParams,
  TokenResponse,
  UserInfoResponse,
} from "./types.js";

/** Error thrown when the Hearth API returns an error. */
export class HearthError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(`Hearth API error ${status}: ${JSON.stringify(body)}`);
    this.name = "HearthError";
  }
}

/** Configuration for HearthClient. */
export interface HearthClientConfig {
  baseUrl: string;
  realmId: string;
}

/**
 * TypeScript client for the Hearth identity API.
 *
 * Wraps the Hearth HTTP API for auth code flows, token management,
 * and JWKS retrieval.
 */
export class HearthClient {
  private readonly baseUrl: string;
  private readonly realmId: string;

  constructor(config: HearthClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.realmId = config.realmId;
  }

  /** POST /admin/bootstrap — create realm, admin user, tokens (dev mode only). */
  static async bootstrap(baseUrl: string): Promise<BootstrapResponse> {
    const url = `${baseUrl.replace(/\/$/, "")}/admin/bootstrap`;
    const resp = await fetch(url, { method: "POST" });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<BootstrapResponse>;
  }

  /** POST /clients — register an OAuth 2.0 client. */
  async registerClient(params: RegisterClientParams): Promise<OAuthClient> {
    return this.post("/clients", {
      client_name: params.clientName,
      redirect_uris: params.redirectUris,
    });
  }

  /** POST /authorize — initiate an authorization code flow. */
  async authorize(params: AuthorizeParams): Promise<AuthorizeResponse> {
    return this.post("/authorize", {
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
      scope: params.scope,
      state: params.state,
      response_type: params.responseType ?? "code",
      user_id: params.userId,
      code_challenge: params.codeChallenge,
      code_challenge_method: params.codeChallengeMethod,
      nonce: params.nonce,
    });
  }

  /** POST /token — exchange an authorization code for tokens. */
  async exchangeCode(params: TokenExchangeParams): Promise<TokenResponse> {
    return this.post("/token", {
      client_id: params.clientId,
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    });
  }

  /** POST /token — refresh tokens using a refresh token. */
  async refreshTokens(
    clientId: string,
    refreshToken: string,
  ): Promise<TokenResponse> {
    return this.post("/token", {
      client_id: clientId,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
  }

  /**
   * POST /v1/authz/check — batch permission check.
   *
   * The subject is always the bearer-token user; only `(object, relation)`
   * pairs are supplied by the caller. Pass the zookie from a previous
   * mutation via `options.zookie` to guarantee read-after-write consistency.
   */
  async check(
    accessToken: string,
    checks: CheckRequestItem[],
    options: { zookie?: number } = {},
  ): Promise<CheckResponse> {
    const body: Record<string, unknown> = { checks };
    if (options.zookie !== undefined) {
      body.at_least_as_fresh_as = options.zookie;
    }
    const resp = await fetch(`${this.baseUrl}/v1/authz/check`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Realm-ID": this.realmId,
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<CheckResponse>;
  }

  /**
   * GET /v1/me/capabilities — fetch the capability bundle for the named page.
   *
   * `page` selects a server-configured capability page; `params` resolve
   * `{var}` placeholders in the page's object templates.
   */
  async capabilities(
    accessToken: string,
    page: string,
    params: Record<string, string> = {},
  ): Promise<CapabilityBundle> {
    const query = new URLSearchParams({ page, ...params });
    const resp = await fetch(
      `${this.baseUrl}/v1/me/capabilities?${query.toString()}`,
      {
        headers: {
          "X-Realm-ID": this.realmId,
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<CapabilityBundle>;
  }

  /** GET /userinfo — retrieve user claims using an access token. */
  async userinfo(accessToken: string): Promise<UserInfoResponse> {
    const resp = await fetch(`${this.baseUrl}/userinfo`, {
      headers: {
        "X-Realm-ID": this.realmId,
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<UserInfoResponse>;
  }

  /** GET /jwks — retrieve the JWKS document. */
  async jwks(): Promise<JwksDocument> {
    const resp = await fetch(`${this.baseUrl}/jwks`);
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<JwksDocument>;
  }

  /** GET /.well-known/openid-configuration — OIDC discovery document. */
  async discovery(): Promise<Record<string, unknown>> {
    const resp = await fetch(
      `${this.baseUrl}/.well-known/openid-configuration`,
    );
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<Record<string, unknown>>;
  }

  /** Creates an AdminClient using the given access token. */
  admin(accessToken: string): AdminClient {
    return new AdminClient(this.baseUrl, this.realmId, accessToken);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Realm-ID": this.realmId,
      },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new HearthError(resp.status, await resp.json());
    }
    return resp.json() as Promise<T>;
  }
}

// AdminClient is imported here to avoid circular deps — it's re-exported from index.
import { AdminClient } from "./admin.js";
