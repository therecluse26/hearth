package io.hearth.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.util.concurrent.TimeUnit

internal val JSON = Json {
    ignoreUnknownKeys = true
    encodeDefaults = false
    isLenient = true
}

private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

/** Builds a shared OkHttpClient with the configured timeout. */
internal fun buildHttpClient(timeoutMs: Long): OkHttpClient =
    OkHttpClient.Builder()
        .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .build()

/** Executes [request] on [client] in the IO dispatcher, returning the raw [Response]. */
internal suspend fun OkHttpClient.executeAsync(request: Request): Response =
    withContext(Dispatchers.IO) { newCall(request).execute() }

/**
 * Executes a GET request to [url] with optional [headers], parses the response body
 * as [T], and throws [ApiError] on non-2xx status.
 */
internal suspend inline fun <reified T> OkHttpClient.get(
    url: String,
    headers: Map<String, String> = emptyMap(),
): T {
    val request = Request.Builder().url(url).apply {
        headers.forEach { (k, v) -> addHeader(k, v) }
    }.get().build()

    executeAsync(request).use { resp ->
        val body = resp.body?.string() ?: ""
        if (!resp.isSuccessful) throw ApiError(resp.code, "HTTP ${resp.code}: $body")
        return JSON.decodeFromString(body)
    }
}

/**
 * Executes a POST request to [url] with JSON-encoded [payload] and optional [headers],
 * parses the response body as [T].
 */
internal suspend inline fun <reified Req, reified Res> OkHttpClient.post(
    url: String,
    payload: Req,
    headers: Map<String, String> = emptyMap(),
): Res {
    val body = JSON.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE)
    val request = Request.Builder().url(url).apply {
        headers.forEach { (k, v) -> addHeader(k, v) }
        post(body)
    }.build()

    executeAsync(request).use { resp ->
        val bodyStr = resp.body?.string() ?: ""
        if (!resp.isSuccessful) throw ApiError(resp.code, "HTTP ${resp.code}: $bodyStr")
        return JSON.decodeFromString(bodyStr)
    }
}

/**
 * Executes a PUT request to [url] with JSON-encoded [payload] and optional [headers].
 */
internal suspend inline fun <reified Req, reified Res> OkHttpClient.put(
    url: String,
    payload: Req,
    headers: Map<String, String> = emptyMap(),
): Res {
    val body = JSON.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE)
    val request = Request.Builder().url(url).apply {
        headers.forEach { (k, v) -> addHeader(k, v) }
        put(body)
    }.build()

    executeAsync(request).use { resp ->
        val bodyStr = resp.body?.string() ?: ""
        if (!resp.isSuccessful) throw ApiError(resp.code, "HTTP ${resp.code}: $bodyStr")
        return JSON.decodeFromString(bodyStr)
    }
}

/**
 * Executes a DELETE request to [url] with optional [headers].
 */
internal suspend fun OkHttpClient.delete(
    url: String,
    headers: Map<String, String> = emptyMap(),
) {
    val request = Request.Builder().url(url).apply {
        headers.forEach { (k, v) -> addHeader(k, v) }
        delete()
    }.build()

    executeAsync(request).use { resp ->
        if (!resp.isSuccessful) {
            val body = resp.body?.string() ?: ""
            throw ApiError(resp.code, "HTTP ${resp.code}: $body")
        }
    }
}
