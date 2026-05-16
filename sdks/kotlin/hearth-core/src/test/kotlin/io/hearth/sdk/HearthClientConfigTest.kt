package io.hearth.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HearthClientConfigTest {

    @Test
    fun `constructor strips trailing slash from issuerUrl`() {
        val client = HearthClient(issuerUrl = "https://auth.example.com/")
        assertEquals("https://auth.example.com", client.issuerUrl)
    }

    @Test
    fun `constructor throws ConfigurationError on blank issuerUrl`() {
        assertFailsWith<ConfigurationError> {
            HearthClient(issuerUrl = "")
        }
    }

    @Test
    fun `constructor throws ConfigurationError on invalid URL`() {
        assertFailsWith<ConfigurationError> {
            HearthClient(issuerUrl = "not-a-url")
        }
    }

    @Test
    fun `hasPermission returns false for blank token`() {
        val client = HearthClient("https://auth.example.com")
        assertFalse(client.hasPermission("", "admin"))
    }

    @Test
    fun `hasRole returns false for malformed token`() {
        val client = HearthClient("https://auth.example.com")
        assertFalse(client.hasRole("invalid.token", "admin"))
    }

    @Test
    fun `hasPermission decodes local JWT claims without network`() {
        val client = HearthClient("https://auth.example.com")
        // Build a fake (unsigned) JWT payload with permissions
        val header = base64url("""{"alg":"none","typ":"JWT"}""")
        val payload = base64url("""{"sub":"u1","permissions":["user:read","user:write"]}""")
        val token = "$header.$payload."
        assertTrue(client.hasPermission(token, "user:read"))
        assertFalse(client.hasPermission(token, "admin"))
    }

    @Test
    fun `hasRole decodes local JWT claims without network`() {
        val client = HearthClient("https://auth.example.com")
        val header = base64url("""{"alg":"none","typ":"JWT"}""")
        val payload = base64url("""{"sub":"u1","roles":["admin","viewer"]}""")
        val token = "$header.$payload."
        assertTrue(client.hasRole(token, "admin"))
        assertFalse(client.hasRole(token, "superuser"))
    }

    private fun base64url(s: String): String =
        java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(s.toByteArray())
}
