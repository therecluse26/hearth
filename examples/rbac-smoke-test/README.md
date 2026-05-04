# RBAC Smoke Test

End-to-end sanity check for Hearth's claims-based RBAC surface. Boots a
`--dev` server, exercises the full lifecycle (create realm, assign
role, issue token, verify permissions, revoke, re-verify), and exits 0
on success.

## Run

```bash
./smoke.sh
```

Assumes `cargo`, `curl`, and `jq` on PATH. The script builds the
`hearth` binary once, spawns it in the background, runs the checks, and
tears it down before exiting. No lingering processes, no leftover data
dirs (temp-dir based).

## What it verifies

1. `/health` returns 200.
2. `POST /admin/bootstrap` yields a realm + admin user + token.
3. Admin token has `hearth.admin` in its `permissions` claim.
4. `GET /admin/roles` returns 200 with seed roles present.
5. Creating a role via `POST /admin/roles` works.
6. `POST /admin/users/{id}/roles` assigns the new role.
7. A fresh token for the subject user now has the new role's
   permissions in its `permissions` claim (resolved at issue time).
8. `GET /v1/me/permissions` returns the live resolved set.
9. Revoking the assignment via `DELETE /admin/assignments/{id}` +
   issuing a new token drops the permissions.
10. A user without `hearth.admin` gets 403 on admin endpoints.

## Expected output

Each step prints a `▸` line followed by the asserted condition. Failure
prints the server response and exits non-zero; success prints a final
`all checks passed` line.
