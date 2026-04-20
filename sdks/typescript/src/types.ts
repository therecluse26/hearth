/** Response from the dev bootstrap endpoint. */
export interface BootstrapResponse {
  realm_id: string;
  user_id: string;
  access_token: string;
  refresh_token: string;
}

/** Parameters for initiating an authorization code flow. */
export interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  responseType?: string;
  userId: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
}

/** Response from the authorize endpoint. */
export interface AuthorizeResponse {
  code: string;
  state: string;
}

/** Parameters for exchanging an authorization code. */
export interface TokenExchangeParams {
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
}

/** Response from the token exchange endpoint. */
export interface TokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

/** UserInfo response from the OIDC UserInfo endpoint. */
export interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
}

/** Parameters for creating a user. */
export interface CreateUserParams {
  email: string;
  displayName: string;
}

/** User record from the API. */
export interface User {
  id: string;
  email: string;
  display_name: string;
  status: string;
  created_at?: number;
  updated_at?: number;
}

/** Parameters for updating a user. */
export interface UpdateUserParams {
  email?: string;
  displayName?: string;
  status?: string;
}

/** Parameters for creating a realm. */
export interface CreateRealmParams {
  name: string;
  config?: Record<string, unknown>;
}

/** Realm record from the API. */
export interface Realm {
  id: string;
  name: string;
  status: string;
  config: Record<string, unknown> | null;
  created_at?: number;
  updated_at?: number;
}

/** Parameters for updating a realm. */
export interface UpdateRealmParams {
  name?: string;
  status?: string;
  config?: Record<string, unknown>;
}

/** Paginated list response. */
export interface PageResponse<T> {
  items: T[];
  next_cursor: string | null;
}

/** Parameters for registering an OAuth client. */
export interface RegisterClientParams {
  clientName: string;
  redirectUris: string[];
}

/** OAuth client record from the API. */
export interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at?: number;
}

/** JWKS document containing public keys. */
export interface JwksDocument {
  keys: JsonWebKey[];
}

/** A single JWK entry. */
export interface JsonWebKey {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  use?: string;
  alg?: string;
}
