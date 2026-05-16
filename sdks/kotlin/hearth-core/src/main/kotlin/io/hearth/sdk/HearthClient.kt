package io.hearth.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient

/** Default HTTP timeout in milliseconds per sdk-spec §1. */
private const val DEFAULT_HTTP_TIMEOUT_MS = 10_000L

/**
 * Primary entry point for the Hearth Kotlin/JVM SDK.
 *
 * Configured once; auto-discovers all endpoint URLs from
 * `{issuerUrl}/.well-known/openid-configuration` on first use.
 * All async methods are `suspend` functions for native coroutine support.
 *
 * Usage:
 * ```kotlin
 * val client = HearthClient(
 *     issuerUrl = "https://auth.example.com",
 *     clientId = "my-app",
 *     clientSecret = "secret",
 * )
 * val claims = client.verifyToken(accessToken)
 * println(claims.subject())
 * ```
 */
class HearthClient(
    issuerUrl: String,
    val clientId: String? = null,
    val clientSecret: String? = null,
    /** Override JWKS cache TTL in milliseconds. Clamped to [JWKS_MIN_TTL_MS, JWKS_MAX_TTL_MS]. */
    jwksTtl: Long? = null,
    /** Override the introspection endpoint URL (skips discovery for this field). */
    private val introspectionEndpointOverride: String? = null,
    /** HTTP timeout in milliseconds. Default: 10 000 ms. */
    httpTimeoutMs: Long = DEFAULT_HTTP_TIMEOUT_MS,
    /** When set, `aud` must contain this value during [verifyToken]. Defaults to [clientId]. */
    private val expectedAudience: String? = null,
) {
    val issuerUrl: String

    private val httpClient: OkHttpClient = buildHttpClient(httpTimeoutMs)
    private val jwksTtl: Long? = jwksTtl

    private val discoveryMutex = Mutex()
    private var _discovery: JsonObject? = null

    private var _jwksClient: JwksClient? = null
    private var _tokenVerifier: TokenVerifier? = null
    private var _introspectionClient: IntrospectionClient? = null

    init {
        if (issuerUrl.isBlank()) {
            throw ConfigurationError("issuerUrl is required")
        }
        try {
            java.net.URL(issuerUrl)
        } catch (e: Exception) {
            throw ConfigurationError("issuerUrl \"$issuerUrl\" is not a valid URL", e)
        }
        this.issuerUrl = issuerUrl.trimEnd('/')
    }

    // ── OIDC Discovery ─────────────────────────────────────────────────────────

    /**
     * Fetches and caches the OIDC discovery document.
     *
     * All endpoint URLs are derived from this document — no paths are hard-coded.
     *
     * @throws DiscoveryError when the endpoint is unreachable, returns non-2xx, or returns invalid JSON.
     */
    suspend fun discover(): JsonObject {
        _discovery?.let { return it }
        return discoveryMutex.withLock {
            _discovery ?: fetchDiscovery().also { _discovery = it }
        }
    }

    private suspend fun fetchDiscovery(): JsonObject {
        val url = "$issuerUrl/.well-known/openid-configuration"
        return try {
            httpClient.get<JsonObject>(url)
        } catch (e: ApiError) {
            throw DiscoveryError("OIDC discovery returned HTTP ${e.statusCode}", e)
        } catch (e: DiscoveryError) {
            throw e
        } catch (e: Exception) {
            throw DiscoveryError("OIDC discovery endpoint unreachable: $url", e)
        }.also { doc ->
            if (!doc.containsKey("jwks_uri")) {
                throw DiscoveryError("OIDC discovery document missing required field: jwks_uri")
            }
        }
    }

    // ── JWKS / Token verification ──────────────────────────────────────────────

    /** Returns the lazily-created, shared [JwksClient] bound to the discovered `jwks_uri`. */
    suspend fun jwksClient(): JwksClient {
        _jwksClient?.let { return it }
        val doc = discover()
        val jwksUri = doc["jwks_uri"]?.jsonPrimitive?.content
            ?: throw DiscoveryError("OIDC discovery document missing jwks_uri")
        return JwksClient(jwksUri, httpClient, jwksTtl).also { _jwksClient = it }
    }

    /** Returns the lazily-created, shared [TokenVerifier]. */
    suspend fun tokenVerifier(): TokenVerifier {
        _tokenVerifier?.let { return it }
        val audience = expectedAudience ?: clientId
        return TokenVerifier(jwksClient(), issuerUrl, audience)
            .also { _tokenVerifier = it }
    }

    /**
     * Verifies [token] and returns the decoded [Claims].
     *
     * @throws TokenInvalidError   on bad signature or malformed JWT
     * @throws TokenExpiredError   when `exp` is in the past
     * @throws TokenIssuerError    when `iss` does not match [issuerUrl]
     * @throws TokenAudienceError  when `aud` check is enabled and fails
     * @throws JWKSFetchError      when the JWKS endpoint is unreachable
     */
    suspend fun verifyToken(token: String): Claims =
        tokenVerifier().verify(token)

    // ── Token introspection ────────────────────────────────────────────────────

    /** Returns the lazily-created, shared [IntrospectionClient]. */
    suspend fun introspectionClient(): IntrospectionClient {
        _introspectionClient?.let { return it }
        if (clientId == null || clientSecret == null) {
            throw ConfigurationError(
                "clientId and clientSecret are required for token introspection"
            )
        }
        val endpoint = introspectionEndpointOverride
            ?: discover()["introspection_endpoint"]?.jsonPrimitive?.content
            ?: throw ConfigurationError(
                "introspection_endpoint is not present in the OIDC discovery document " +
                "and no introspectionEndpointOverride was provided"
            )
        return IntrospectionClient(endpoint, clientId, clientSecret, httpClient)
            .also { _introspectionClient = it }
    }

    /**
     * Introspects [token] per RFC 7662. Results are never cached.
     *
     * @throws ConfigurationError  when clientId/clientSecret are not set
     * @throws IntrospectionError  when the endpoint is unreachable or returns an error
     */
    suspend fun introspect(token: String): IntrospectionResult =
        introspectionClient().introspect(token)

    // ── OAuth flows ────────────────────────────────────────────────────────────

    private suspend fun tokenEndpoint(): String =
        discover()["token_endpoint"]?.jsonPrimitive?.content
            ?: throw DiscoveryError("OIDC discovery document missing token_endpoint")

    private suspend fun authorizationEndpoint(): String =
        discover()["authorization_endpoint"]?.jsonPrimitive?.content
            ?: throw DiscoveryError("OIDC discovery document missing authorization_endpoint")

    private suspend fun deviceAuthorizationEndpoint(): String =
        discover()["device_authorization_endpoint"]?.jsonPrimitive?.content
            ?: throw DiscoveryError("OIDC discovery document missing device_authorization_endpoint")

    /**
     * Initiates an authorization code flow (with optional PKCE).
     *
     * Returns the authorization redirect URL; the caller should redirect the user to it.
     */
    suspend fun authorize(request: AuthorizeRequest): AuthorizeResponse {
        val endpoint = authorizationEndpoint()
        return try {
            httpClient.post(endpoint, request)
        } catch (e: ApiError) {
            throw HearthException("Authorization endpoint returned HTTP ${e.statusCode}", e)
        }
    }

    /**
     * Exchanges an authorization code for tokens (Authorization Code Flow).
     */
    suspend fun exchangeCode(
        code: String,
        redirectUri: String,
        codeVerifier: String? = null,
    ): TokenResponse {
        val cId = clientId
            ?: throw ConfigurationError("clientId is required for authorization code exchange")
        return exchangeToken(
            TokenRequest(
                clientId = cId,
                grantType = "authorization_code",
                code = code,
                redirectUri = redirectUri,
                codeVerifier = codeVerifier,
                clientSecret = clientSecret,
            )
        )
    }

    /**
     * Refreshes tokens using a [refreshToken] (Refresh Token Flow).
     */
    suspend fun refreshTokens(refreshToken: String): TokenResponse {
        val cId = clientId
            ?: throw ConfigurationError("clientId is required for refresh token flow")
        return exchangeToken(
            TokenRequest(
                clientId = cId,
                grantType = "refresh_token",
                refreshToken = refreshToken,
                clientSecret = clientSecret,
            )
        )
    }

    /**
     * Obtains tokens using client credentials (Client Credentials Flow).
     * Requires [clientId] and [clientSecret].
     */
    suspend fun clientCredentials(scope: String? = null): TokenResponse {
        val cId = clientId
            ?: throw ConfigurationError("clientId is required for client credentials flow")
        val cSecret = clientSecret
            ?: throw ConfigurationError("clientSecret is required for client credentials flow")
        return exchangeToken(
            TokenRequest(
                clientId = cId,
                grantType = "client_credentials",
                clientSecret = cSecret,
                scope = scope,
            )
        )
    }

    /**
     * Initiates the Device Authorization Flow (RFC 8628).
     *
     * Returns a [DeviceAuthorizationResponse] with the `user_code` to display
     * and the `device_code` to poll with [pollDeviceToken].
     */
    suspend fun deviceAuthorization(scope: String? = null): DeviceAuthorizationResponse {
        val cId = clientId
            ?: throw ConfigurationError("clientId is required for device authorization flow")
        val endpoint = deviceAuthorizationEndpoint()
        return try {
            httpClient.post(endpoint, DeviceAuthorizationRequest(cId, scope))
        } catch (e: ApiError) {
            throw HearthException("Device authorization endpoint returned HTTP ${e.statusCode}", e)
        }
    }

    /**
     * Polls the token endpoint for Device Flow completion.
     *
     * Returns [TokenResponse] when the user has authorized, or null when still pending
     * (authorization_pending / slow_down). Throws [HearthException] on fatal errors.
     */
    suspend fun pollDeviceToken(deviceCode: String): TokenResponse? {
        val cId = clientId
            ?: throw ConfigurationError("clientId is required for device flow polling")
        return try {
            exchangeToken(
                TokenRequest(
                    clientId = cId,
                    grantType = "urn:ietf:params:oauth:grant-type:device_code",
                    deviceCode = deviceCode,
                    clientSecret = clientSecret,
                )
            )
        } catch (e: ApiError) {
            val body = e.message ?: ""
            if (body.contains("authorization_pending") || body.contains("slow_down")) {
                null
            } else {
                throw e
            }
        }
    }

    /**
     * Exchanges a Magic Link token for tokens.
     */
    suspend fun exchangeMagicLink(magicToken: String): TokenResponse {
        val cId = clientId
            ?: throw ConfigurationError("clientId is required for magic link exchange")
        return exchangeToken(
            TokenRequest(
                clientId = cId,
                grantType = "urn:hearth:grant-type:magic-link",
                token = magicToken,
            )
        )
    }

    private suspend fun exchangeToken(request: TokenRequest): TokenResponse {
        val endpoint = tokenEndpoint()
        return try {
            httpClient.post(endpoint, request)
        } catch (e: ApiError) {
            throw HearthException("Token endpoint returned HTTP ${e.statusCode}", e)
        }
    }

    // ── UserInfo ───────────────────────────────────────────────────────────────

    /**
     * Fetches user claims from the OIDC UserInfo endpoint using [accessToken].
     */
    suspend fun userInfo(accessToken: String): UserInfoResponse {
        val endpoint = discover()["userinfo_endpoint"]?.jsonPrimitive?.content
            ?: throw DiscoveryError("OIDC discovery document missing userinfo_endpoint")
        return httpClient.get(
            endpoint,
            mapOf("Authorization" to "Bearer $accessToken"),
        )
    }

    // ── Bootstrap (dev/test only) ──────────────────────────────────────────────

    /**
     * Calls `POST /admin/bootstrap` in dev mode.
     *
     * Creates a realm, admin user, session, and admin role assignment.
     * **Not available in production deployments.**
     */
    suspend fun bootstrap(): BootstrapResponse = withContext(Dispatchers.IO) {
        val request = okhttp3.Request.Builder()
            .url("$issuerUrl/admin/bootstrap")
            .post(okhttp3.RequestBody.create(null, ByteArray(0)))
            .build()
        httpClient.executeAsync(request).use { resp ->
            val body = resp.body?.string() ?: ""
            if (!resp.isSuccessful) throw ApiError(resp.code, "HTTP ${resp.code}: $body")
            JSON.decodeFromString(body)
        }
    }

    // ── Admin ──────────────────────────────────────────────────────────────────

    /**
     * Returns an [AdminClient] for administrative operations using [accessToken].
     *
     * The admin token is not stored in [HearthClient] — a new [AdminClient] is
     * returned each time, keeping credential lifetime explicit.
     */
    fun admin(accessToken: String): AdminClient =
        AdminClient(issuerUrl, accessToken, httpClient)

    // ── RBAC helpers (local, no network) ──────────────────────────────────────

    /**
     * Returns true iff [token]'s `permissions` claim contains [permission].
     *
     * Decoding is local — no network call. Returns false for empty or malformed tokens.
     * The token signature is NOT verified here; use [verifyToken] for that.
     */
    fun hasPermission(token: String, permission: String): Boolean =
        decodeLocalClaims(token)?.get("permissions")
            ?.let { it as? List<*> }
            ?.contains(permission) == true

    /**
     * Returns true iff [token]'s `roles` claim contains [role].
     *
     * Decoding is local — no network call.
     */
    fun hasRole(token: String, role: String): Boolean =
        decodeLocalClaims(token)?.get("roles")
            ?.let { it as? List<*> }
            ?.contains(role) == true

    private fun decodeLocalClaims(token: String): Map<String, Any?>? {
        if (token.isBlank()) return null
        val parts = token.split(".")
        if (parts.size != 3) return null
        return try {
            val payload = java.util.Base64.getUrlDecoder().decode(
                parts[1].padEnd((parts[1].length + 3) / 4 * 4, '=')
            )
            @Suppress("UNCHECKED_CAST")
            JSON.parseToJsonElement(String(payload))
                .jsonObject
                .mapValues { (_, v) -> extractAny(v) }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractAny(el: kotlinx.serialization.json.JsonElement): Any? = when (el) {
        is kotlinx.serialization.json.JsonPrimitive ->
            el.booleanOrNull ?: el.longOrNull ?: el.doubleOrNull ?: el.contentOrNull
        is kotlinx.serialization.json.JsonArray ->
            el.map { extractAny(it) }
        is kotlinx.serialization.json.JsonObject ->
            el.mapValues { (_, v) -> extractAny(v) }
        else -> null
    }
}
