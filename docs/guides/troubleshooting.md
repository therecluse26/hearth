# Troubleshooting

This guide covers the most common errors operators encounter when running Hearth, with root cause and exact remediation steps for each.

---

## Login failures

### "Invalid credentials"

**Symptoms:** Login attempt returns an error indicating the username or password is wrong.

**Root causes and checks:**

1. **Wrong realm.** Each realm is isolated. Confirm the login request targets the correct realm name in the URL (`/ui/realms/<realm-name>/login`). A user that exists in `acme` cannot log in through `other-realm`.

2. **User does not exist.** Check in the admin UI under **Users** for the target realm, or query via the API:
   ```bash
   curl -H "Authorization: Bearer <admin-token>" \
     http://127.0.0.1:8420/admin/realms/<realm-id>/users?email=user@example.com
   ```

3. **Password hash algorithm mismatch (post-migration).** Users migrated from Keycloak with PBKDF2-SHA256 credentials work natively — Hearth verifies PBKDF2-SHA256 without re-hashing. Users migrated from Auth0 with bcrypt credentials also work natively. If a user was imported with an unsupported hash algorithm the import report will have noted it, and that user will have no usable credential. The user must reset their password via the passwordless / magic-link flow.

4. **Account disabled.** A user with `status: disabled` cannot log in. Re-enable via the admin UI (`/ui/admin/realms/<realm>/users/<id>`) or the API:
   ```bash
   curl -X PUT http://127.0.0.1:8420/admin/realms/<realm-id>/users/<user-id> \
     -H "Authorization: Bearer <admin-token>" \
     -H "Content-Type: application/json" \
     -d '{"status": "Active"}'
   ```

---

### "MFA required" / user locked out of MFA device

**Symptom:** A user has lost their TOTP app or recovery codes and cannot complete the MFA step.

**Remediation — admin UI:**
1. Go to `/ui/admin/realms/<realm-name>/users/<user-id>`.
2. Click **Reset MFA codes**.
3. Share the new recovery codes with the user over a separate channel.
4. The user can then log in with a recovery code and re-enroll their TOTP device.

**Remediation — API:**
```bash
curl -X POST http://127.0.0.1:8420/admin/realms/<realm>/users/<user-id>/reset-mfa-codes \
  -H "Authorization: Bearer <admin-token>"
```

The response contains the new single-use recovery codes. Store or transmit them securely — they are not shown again.

---

### "Realm suspended"

**Symptom:** All logins for a realm fail with a realm-suspended error.

**Cause:** The realm was explicitly suspended via the admin API or UI.

**Remediation:**
```bash
curl -X PUT http://127.0.0.1:8420/admin/realms/<realm-id> \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"status": "Active"}'
```

You can also reactivate from the admin UI: navigate to `/ui/admin/realms/<realm-id>` and click **Reactivate**.

---

### "Token expired" / refresh fails

**Symptom:** An access token is rejected with an expiry error; attempting a token refresh also fails.

**Root causes:**

- **Access token expired, no refresh token.** Access tokens are short-lived by design. The client application must implement the refresh token flow: exchange the refresh token at `POST /token` with `grant_type=refresh_token`. If the client did not store the refresh token, the user must re-authenticate.

- **Refresh token expired.** Refresh tokens have their own lifetime. Check the `token.refresh_token_ttl` value in your `hearth.yaml`:
  ```yaml
  token:
    refresh_token_ttl: "14d"   # default if unset
  ```
  If the user was inactive longer than the refresh lifetime, they must log in again.

- **Token revoked.** Sessions can be revoked via the admin API or by a logout event. The client must redirect the user to the login page.

- **Clock skew.** The server rejects tokens with `nbf` in the future. Ensure the server and client clocks are synchronized (NTP).

**Changing token lifetimes** — edit `hearth.yaml` and reload:
```yaml
token:
  access_token_ttl: "15m"   # ISO-8601 duration string
  refresh_token_ttl: "7d"
```
Then run:
```bash
hearth config reload
```

---

## Configuration issues

### Missing `hearth.yaml`

**Symptom:** Server refuses to start with a "config file not found" error.

**Cause:** Hearth looks for `hearth.yaml` in the current working directory by default. An empty file is a valid configuration (all defaults apply).

**Remediation:**
```bash
cp hearth.example.yaml hearth.yaml
# Edit hearth.yaml as needed, then:
./hearth serve
```

To use a config file at a non-default path:
```bash
./hearth serve -c /etc/hearth/hearth.yaml
```

**Validate a config file without starting the server:**
```bash
hearth config validate hearth.yaml
```
This command exits 0 on success and exits 1 with a detailed error list on failure.

---

### TLS certificate not found

**Symptom:** Server fails to start with a "TLS cert" or "no such file" error.

**Cause:** `server.tls_cert_path` or `server.tls_key_path` points to a file that does not exist, is not readable, or is not a valid PEM.

**Checks:**

1. Confirm the paths are correct and readable:
   ```bash
   ls -la /path/to/server.crt /path/to/server.key
   openssl x509 -in /path/to/server.crt -noout -subject -dates
   openssl rsa -in /path/to/server.key -check -noout
   ```

2. Both fields must be set together — setting one without the other is a validation error:
   ```yaml
   server:
     tls_cert_path: /etc/hearth/tls/server.crt
     tls_key_path:  /etc/hearth/tls/server.key
   ```

3. Run `hearth config validate hearth.yaml` — it catches the missing-pair case and reports the field name.

4. The process user must have read access to both files:
   ```bash
   sudo -u hearth cat /etc/hearth/tls/server.key > /dev/null
   ```

---

### Email transport not sending

**Symptom:** Verification emails, magic links, or invitation emails are never received.

**Step 1 — Check the configured transport.**

The default transport is `log`, which writes the email body to the server log (not to an inbox). Confirm you have configured a real transport:
```yaml
email:
  transport: smtp   # or sendgrid, postmark, mailgun, mailtrap
```

**Step 2 — Validate the config.**
```bash
hearth config validate hearth.yaml
```
This checks that required API keys and SMTP credentials are present.

**Step 3 — Watch the logs.** On `transport: log`, email bodies appear at `WARN` level:
```bash
./hearth serve 2>&1 | grep -i "email\|verification\|magic"
```

**Step 4 — Test the SMTP connection manually:**
```bash
openssl s_client -connect smtp.example.com:587 -starttls smtp
```

**Step 5 — Check spam folders and envelope addresses.** Ensure `email.from` is set to an address your provider accepts as a sender.

---

### Port already in use

**Symptom:** Server exits immediately with "address already in use" or `EADDRINUSE`.

**Cause:** Another process is bound to `127.0.0.1:8420` (the default).

**Check what is using the port:**
```bash
ss -tlnp | grep 8420
lsof -i :8420
```

**Remediation — change the bind port:**
```yaml
server:
  port: 9000
  bind_address: "0.0.0.0"   # or keep 127.0.0.1
```
Or override on the command line:
```bash
hearth serve --port 9000 --bind 0.0.0.0
```

---

## Storage issues

### WAL corruption on startup

**Symptom:** Server refuses to start with a WAL CRC error or "corrupt record" message.

**Root cause:** The WAL tail is incomplete — typically from an unclean shutdown (power loss, `kill -9`) where the final write was not fully flushed.

**Hearth's recovery behavior:**
- The WAL replayer discards any trailing record whose CRC does not match. Writes are atomic at the record level.
- In most unclean-shutdown scenarios the server will replay cleanly and the potentially-incomplete tail record is automatically dropped.
- If the server still fails to start after an unclean shutdown, the WAL may have a more severe corruption.

**Recovery procedure:**

1. **Take a backup first.**
   ```bash
   cp -a /var/lib/hearth /var/lib/hearth.bak-$(date +%Y%m%d%H%M%S)
   ```

2. **Attempt a normal start** — Hearth skips tail-corrupt records automatically.

3. **If startup still fails,** inspect logs for the specific error. If the corruption is in the middle of the WAL (not just the tail), contact the Hearth project for recovery tooling. Do not delete `hearth.wal` without understanding which records will be lost.

4. **Prevent recurrence:** ensure `storage.fsync: true` (the default) and that the filesystem is not mounted `nobarrier`.

---

### Storage path permissions

**Symptom:** Server exits with "permission denied" accessing the data directory.

**Required permissions:**
- The Hearth process user must have **read + write + execute** on the data directory itself.
- The data directory should not be world-readable (`chmod 700 /var/lib/hearth`).

**Remediation:**
```bash
chown -R hearth:hearth /var/lib/hearth
chmod 700 /var/lib/hearth
```

Verify the process user can actually write:
```bash
sudo -u hearth touch /var/lib/hearth/.write-test && echo ok
```

---

## SDK / integration issues

### CORS errors

**Symptom:** Browser console shows `Access-Control-Allow-Origin` errors when your SPA calls Hearth endpoints.

**Cause:** Hearth must be told which origins to trust. This is configured per-realm in `hearth.yaml`:

```yaml
realms:
  my-realm:
    auth:
      allowed_origins:
        - "https://app.example.com"
        - "http://localhost:3000"   # development only
```

After changing `hearth.yaml`, reload without a restart:
```bash
hearth config reload
```

**Do not use `*` as an allowed origin** in production — Hearth does not support wildcard origins because doing so would allow any site to make authenticated cross-origin requests.

---

### JWT signature verification failure

**Symptom:** Your application's JWT library rejects tokens from Hearth with a signature verification error even when the token looks valid.

**Common causes:**

1. **Wrong JWKS URL.** The JWKS endpoint is:
   ```
   GET /.well-known/jwks.json
   ```
   Some libraries default to an incorrect path. Confirm by fetching it directly:
   ```bash
   curl http://127.0.0.1:8420/.well-known/jwks.json
   ```

2. **Stale cached keys after key rotation.** Hearth rotates signing keys per-realm. If your application caches the JWKS document indefinitely it will hold a stale public key. Configure your JWT library to honor the `Cache-Control` header or set a short TTL (5–15 minutes) on the JWKS cache.

3. **Algorithm mismatch.** Hearth signs tokens with **Ed25519** by default. Some libraries require explicit algorithm allow-listing. Ensure `EdDSA` (or `Ed25519`) is in your allowed list.

4. **Issuer mismatch.** The `iss` claim in the token is set from `oidc.issuer` in `hearth.yaml`. Ensure your library's expected issuer matches exactly (scheme, host, port, no trailing slash):
   ```yaml
   oidc:
     issuer: "https://auth.example.com"
   ```

---

### Redirect URI mismatch

**Symptom:** Authorization request fails with `redirect_uri_mismatch` or the login page shows "Invalid redirect URI".

**Cause:** The `redirect_uri` parameter in the authorization request does not exactly match any URI registered on the OAuth application.

**Remediation:**

1. Go to the admin UI: `/ui/admin/applications/<client-id>/edit`.
2. Add or correct the redirect URI in the **Allowed Redirect URIs** field. The match is exact — trailing slashes, schemes (`http` vs `https`), and ports must match character-for-character.
3. Save changes.

**Common pitfalls:**
- `http://localhost:3000/callback` and `http://localhost:3000/callback/` are different URIs.
- `http://` and `https://` are different schemes — use HTTPS in production.
- Port number in URI must match what the browser actually sends.

To inspect the registered URIs for an application via the API:
```bash
curl -H "Authorization: Bearer <admin-token>" \
  http://127.0.0.1:8420/admin/applications/<client-id>
```

Look at the `redirect_uris` array in the response.
