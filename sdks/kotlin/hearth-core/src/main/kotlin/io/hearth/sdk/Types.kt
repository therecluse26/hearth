package io.hearth.sdk

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

// ── OAuth / Token types ──────────────────────────────────────────────────────

@Serializable
data class BootstrapResponse(
    @SerialName("realm_id") val realmId: String,
    @SerialName("user_id") val userId: String,
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String,
)

@Serializable
data class AuthorizeRequest(
    @SerialName("client_id") val clientId: String,
    @SerialName("redirect_uri") val redirectUri: String,
    val scope: String,
    val state: String,
    @SerialName("response_type") val responseType: String = "code",
    @SerialName("user_id") val userId: String? = null,
    @SerialName("code_challenge") val codeChallenge: String? = null,
    @SerialName("code_challenge_method") val codeChallengeMethod: String? = null,
    val nonce: String? = null,
)

@Serializable
data class AuthorizeResponse(
    val code: String,
    val state: String,
)

@Serializable
data class TokenRequest(
    @SerialName("client_id") val clientId: String,
    @SerialName("grant_type") val grantType: String? = null,
    val code: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("code_verifier") val codeVerifier: String? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("client_secret") val clientSecret: String? = null,
    // Device flow
    @SerialName("device_code") val deviceCode: String? = null,
    // Client credentials
    val scope: String? = null,
    // Magic link
    val token: String? = null,
)

@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("token_type") val tokenType: String,
    @SerialName("expires_in") val expiresIn: Int? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
)

@Serializable
data class DeviceAuthorizationRequest(
    @SerialName("client_id") val clientId: String,
    val scope: String? = null,
)

@Serializable
data class DeviceAuthorizationResponse(
    @SerialName("device_code") val deviceCode: String,
    @SerialName("user_code") val userCode: String,
    @SerialName("verification_uri") val verificationUri: String,
    @SerialName("verification_uri_complete") val verificationUriComplete: String? = null,
    @SerialName("expires_in") val expiresIn: Int,
    val interval: Int = 5,
)

@Serializable
data class UserInfoResponse(
    val sub: String,
    val name: String? = null,
    val email: String? = null,
    @SerialName("email_verified") val emailVerified: Boolean? = null,
)

@Serializable
data class MePermissionsResponse(
    val roles: List<String>,
    val groups: List<String>,
    val permissions: List<String>,
    val scope: String,
)

// ── OAuth Client registration ─────────────────────────────────────────────────

@Serializable
data class RegisterClientRequest(
    @SerialName("client_name") val clientName: String,
    @SerialName("redirect_uris") val redirectUris: List<String>,
)

@Serializable
data class OAuthClient(
    @SerialName("client_id") val clientId: String,
    @SerialName("client_name") val clientName: String,
    @SerialName("redirect_uris") val redirectUris: List<String>,
    @SerialName("grant_types") val grantTypes: List<String>,
    @SerialName("created_at") val createdAt: Long? = null,
)

// ── Admin — Users ─────────────────────────────────────────────────────────────

@Serializable
data class CreateUserRequest(
    val email: String,
    @SerialName("display_name") val displayName: String,
)

@Serializable
data class User(
    val id: String,
    val email: String,
    @SerialName("display_name") val displayName: String,
    val status: String,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

@Serializable
data class UpdateUserRequest(
    val email: String? = null,
    @SerialName("display_name") val displayName: String? = null,
    val status: String? = null,
)

// ── Admin — Realms ────────────────────────────────────────────────────────────

@Serializable
data class CreateRealmRequest(
    val name: String,
    val config: JsonObject? = null,
)

@Serializable
data class Realm(
    val id: String,
    val name: String,
    val status: String,
    val config: JsonObject? = null,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
)

@Serializable
data class UpdateRealmRequest(
    val name: String? = null,
    val status: String? = null,
    val config: JsonObject? = null,
)

// ── Pagination ────────────────────────────────────────────────────────────────

@Serializable
data class PageResponse<T>(
    val items: List<T>,
    @SerialName("next_cursor") val nextCursor: String? = null,
)

// ── Introspection ─────────────────────────────────────────────────────────────

@Serializable
data class IntrospectionResult(
    val active: Boolean,
    val sub: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    val iss: String? = null,
    val aud: kotlinx.serialization.json.JsonElement? = null,
    val scope: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    /** All non-standard claims captured from the server response. */
    val extra: Map<String, kotlinx.serialization.json.JsonElement> = emptyMap(),
)
