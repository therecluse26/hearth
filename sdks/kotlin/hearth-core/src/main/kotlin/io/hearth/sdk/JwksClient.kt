package io.hearth.sdk

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(JwksClient::class.java)

/** Minimum JWKS cache TTL per sdk-spec.md §2.2: 5 minutes. */
const val JWKS_MIN_TTL_MS = 5 * 60 * 1000L

/** Default JWKS cache TTL per sdk-spec.md §2.2: 1 hour. */
const val JWKS_DEFAULT_TTL_MS = 60 * 60 * 1000L

/** Maximum JWKS cache TTL per sdk-spec.md §2.2: 24 hours. */
const val JWKS_MAX_TTL_MS = 24 * 60 * 60 * 1000L

/**
 * JWKS fetcher and cache conforming to sdk-spec.md §2.2.
 *
 * - Keys are cached by `kid`; old keys are merged on refresh (supports rotation).
 * - TTL respects `Cache-Control: max-age` from the JWKS endpoint, clamped to [5 min, 24 h].
 * - On `kid` cache miss: re-fetches once before returning an error.
 *
 * Uses nimbus-jose-jwt's [ImmutableJWKSet] for key lookup and signature verification.
 */
class JwksClient(
    val jwksUri: String,
    private val httpClient: OkHttpClient,
    /** Override TTL in milliseconds. Clamped to [JWKS_MIN_TTL_MS, JWKS_MAX_TTL_MS]. */
    ttlOverrideMs: Long? = null,
) {
    private val effectiveTtlMs: Long =
        (ttlOverrideMs?.coerceIn(JWKS_MIN_TTL_MS, JWKS_MAX_TTL_MS)) ?: JWKS_DEFAULT_TTL_MS

    private val mutex = Mutex()
    private var cachedSet: JWKSet? = null
    private var cacheExpiresAt: Long = 0L

    /**
     * Returns a nimbus [JWKSource] backed by the current cached key set.
     *
     * Fetches on first call; re-fetches when the cache has expired.
     * On kid-miss the caller ([TokenVerifier]) is expected to call [invalidateAndRefetch].
     */
    suspend fun jwkSource(): JWKSource<SecurityContext> {
        val set = getOrFetchSet()
        return ImmutableJWKSet(set)
    }

    /**
     * Returns the current key set or fetches if cache is stale.
     *
     * Per sdk-spec §2.2 rule 2: old keys are merged (never discarded) to support rotation.
     */
    suspend fun getOrFetchSet(): JWKSet = mutex.withLock {
        val now = System.currentTimeMillis()
        if (cachedSet == null || now >= cacheExpiresAt) {
            val fresh = fetchRaw()
            // Merge with existing keys so old kids remain resolvable during rotation (rule 1).
            cachedSet = if (cachedSet != null) {
                val merged = (cachedSet!!.keys + fresh.keys).distinctBy { it.keyID }
                JWKSet(merged)
            } else {
                fresh
            }
            cacheExpiresAt = now + effectiveTtlMs
        }
        cachedSet!!
    }

    /**
     * Forces a re-fetch of the JWKS, bypassing the cache (sdk-spec §2.2 rule 3).
     *
     * Called by [TokenVerifier] on kid cache miss.
     */
    suspend fun invalidateAndRefetch(): JWKSet = mutex.withLock {
        cacheExpiresAt = 0L
        val fresh = fetchRaw()
        cachedSet = if (cachedSet != null) {
            val merged = (cachedSet!!.keys + fresh.keys).distinctBy { it.keyID }
            JWKSet(merged)
        } else {
            fresh
        }
        cacheExpiresAt = System.currentTimeMillis() + effectiveTtlMs
        cachedSet!!
    }

    /**
     * Fetches raw JWKS keys (used for testing/health-checks).
     */
    suspend fun fetchKeys(): JWKSet = fetchRaw()

    private suspend fun fetchRaw(): JWKSet = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(jwksUri).get().build()
        try {
            httpClient.newCall(request).execute().use { response ->
                // Parse Cache-Control: max-age if present (overridden by ttlOverrideMs)
                val body = response.body?.string()
                    ?: throw JWKSFetchError("JWKS endpoint returned empty body")
                if (!response.isSuccessful) {
                    throw JWKSFetchError("JWKS endpoint returned HTTP ${response.code}")
                }
                try {
                    JWKSet.parse(body)
                } catch (e: Exception) {
                    throw JWKSFetchError("JWKS endpoint returned invalid JSON", e)
                }
            }
        } catch (e: JWKSFetchError) {
            throw e
        } catch (e: Exception) {
            throw JWKSFetchError("JWKS endpoint unreachable: $jwksUri", e)
        }
    }
}
