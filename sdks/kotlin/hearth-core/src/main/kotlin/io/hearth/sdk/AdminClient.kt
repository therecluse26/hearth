package io.hearth.sdk

import okhttp3.OkHttpClient

/**
 * Admin API client for Hearth.
 *
 * Obtained via [HearthClient.admin]. All operations require a valid admin access token
 * and target the `/admin/*` endpoints which enforce RBAC admin role checks.
 *
 * ```kotlin
 * val admin = client.admin(adminAccessToken)
 * val user = admin.createUser(CreateUserRequest("alice@example.com", "Alice"))
 * ```
 */
class AdminClient internal constructor(
    private val baseUrl: String,
    private val accessToken: String,
    private val httpClient: OkHttpClient,
) {
    private fun authHeaders(): Map<String, String> =
        mapOf("Authorization" to "Bearer $accessToken")

    // ── Users ──────────────────────────────────────────────────────────────────

    /** Creates a new user. */
    suspend fun createUser(request: CreateUserRequest): User =
        httpClient.post("$baseUrl/admin/users", request, authHeaders())

    /** Retrieves a user by [userId]. */
    suspend fun getUser(userId: String): User =
        httpClient.get("$baseUrl/admin/users/$userId", authHeaders())

    /** Updates a user. Only non-null fields are changed. */
    suspend fun updateUser(userId: String, request: UpdateUserRequest): User =
        httpClient.put("$baseUrl/admin/users/$userId", request, authHeaders())

    /** Deletes a user permanently. */
    suspend fun deleteUser(userId: String): Unit =
        httpClient.delete("$baseUrl/admin/users/$userId", authHeaders())

    /** Lists users with optional pagination. Returns a [PageResponse]. */
    suspend fun listUsers(limit: Int = 20, cursor: String? = null): PageResponse<User> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/users$q", authHeaders())
    }

    // ── Realms ─────────────────────────────────────────────────────────────────

    /** Creates a new realm. */
    suspend fun createRealm(request: CreateRealmRequest): Realm =
        httpClient.post("$baseUrl/admin/realms", request, authHeaders())

    /** Retrieves a realm by [realmId]. */
    suspend fun getRealm(realmId: String): Realm =
        httpClient.get("$baseUrl/admin/realms/$realmId", authHeaders())

    /** Updates a realm. Only non-null fields are changed. */
    suspend fun updateRealm(realmId: String, request: UpdateRealmRequest): Realm =
        httpClient.put("$baseUrl/admin/realms/$realmId", request, authHeaders())

    /** Deletes a realm permanently. */
    suspend fun deleteRealm(realmId: String): Unit =
        httpClient.delete("$baseUrl/admin/realms/$realmId", authHeaders())

    /** Lists realms with optional pagination. */
    suspend fun listRealms(limit: Int = 20, cursor: String? = null): PageResponse<Realm> {
        val q = buildQueryString(mapOf("limit" to limit.toString(), "cursor" to cursor))
        return httpClient.get("$baseUrl/admin/realms$q", authHeaders())
    }

    // ── OAuth Clients ──────────────────────────────────────────────────────────

    /** Registers a new OAuth 2.0 client. */
    suspend fun registerClient(request: RegisterClientRequest): OAuthClient =
        httpClient.post("$baseUrl/clients", request, authHeaders())

    // ── SCIM-compatible bulk operations ────────────────────────────────────────

    /**
     * Lists users whose email matches [emailPrefix] (SCIM-style filter).
     * Uses the standard list endpoint with a `q` query parameter.
     */
    suspend fun findUsersByEmail(emailPrefix: String, limit: Int = 20): PageResponse<User> {
        val q = buildQueryString(mapOf("q" to emailPrefix, "limit" to limit.toString()))
        return httpClient.get("$baseUrl/admin/users$q", authHeaders())
    }

    // ── Role / Group assignment ────────────────────────────────────────────────

    /**
     * Assigns [role] to [userId].
     *
     * Implementation note: Hearth exposes role assignment via the user roles endpoint.
     */
    suspend fun assignRole(userId: String, role: String): User {
        @kotlinx.serialization.Serializable
        data class RoleRequest(val roles: List<String>)
        return httpClient.put(
            "$baseUrl/admin/users/$userId/roles",
            RoleRequest(listOf(role)),
            authHeaders(),
        )
    }

    private fun buildQueryString(params: Map<String, String?>): String {
        val parts = params.entries
            .filter { !it.value.isNullOrBlank() }
            .joinToString("&") { "${it.key}=${it.value}" }
        return if (parts.isEmpty()) "" else "?$parts"
    }
}
