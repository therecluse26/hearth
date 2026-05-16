package io.hearth.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.Base64

/**
 * RFC 7662 token introspection client.
 *
 * Results are **never cached** — per RFC 7662 §2.1, token state can change at any time.
 * Credentials are sent via HTTP Basic (client_id:client_secret) as per RFC 7662 §2.1.
 *
 * Tokens and secrets never appear in thrown error messages per sdk-spec §11.
 */
class IntrospectionClient(
    private val introspectionEndpoint: String,
    private val clientId: String,
    private val clientSecret: String,
    private val httpClient: OkHttpClient,
) {
    /**
     * Introspects [token] at the introspection endpoint.
     *
     * Results are never cached. Returns an [IntrospectionResult] with [IntrospectionResult.active]
     * set to false when the token is unknown or invalid.
     *
     * @throws IntrospectionError when the endpoint is unreachable or returns a non-2xx response.
     */
    suspend fun introspect(token: String): IntrospectionResult = withContext(Dispatchers.IO) {
        val credentials = Base64.getEncoder()
            .encodeToString("$clientId:$clientSecret".toByteArray())

        val formBody = FormBody.Builder()
            .add("token", token)
            .build()

        val request = Request.Builder()
            .url(introspectionEndpoint)
            .post(formBody)
            .header("Authorization", "Basic $credentials")
            .build()

        val response = try {
            httpClient.newCall(request).execute()
        } catch (e: Exception) {
            throw IntrospectionError("Introspection endpoint unreachable", e)
        }

        response.use { resp ->
            if (!resp.isSuccessful) {
                throw IntrospectionError("Introspection endpoint returned HTTP ${resp.code}")
            }
            val bodyStr = resp.body?.string()
                ?: throw IntrospectionError("Introspection endpoint returned empty body")

            parseIntrospectionResult(bodyStr)
        }
    }

    private fun parseIntrospectionResult(bodyStr: String): IntrospectionResult {
        val jsonObj: JsonObject = try {
            JSON.parseToJsonElement(bodyStr).jsonObject
        } catch (e: Exception) {
            throw IntrospectionError("Introspection endpoint returned invalid JSON", e)
        }

        // Known standard RFC 7662 fields — everything else goes into `extra`
        val knownKeys = setOf("active", "sub", "exp", "iat", "iss", "aud", "scope", "client_id")
        val extra = jsonObj.entries
            .filter { it.key !in knownKeys }
            .associate { it.key to it.value }

        return IntrospectionResult(
            active = jsonObj["active"]?.jsonPrimitive?.boolean ?: false,
            sub = jsonObj["sub"]?.jsonPrimitive?.contentOrNull,
            exp = jsonObj["exp"]?.jsonPrimitive?.longOrNull,
            iat = jsonObj["iat"]?.jsonPrimitive?.longOrNull,
            iss = jsonObj["iss"]?.jsonPrimitive?.contentOrNull,
            aud = jsonObj["aud"],
            scope = jsonObj["scope"]?.jsonPrimitive?.contentOrNull,
            clientId = jsonObj["client_id"]?.jsonPrimitive?.contentOrNull,
            extra = extra,
        )
    }
}
