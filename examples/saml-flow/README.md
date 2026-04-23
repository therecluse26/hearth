# SAML 2.0 Flow — Runnable Example

End-to-end demo of Hearth's SAML 2.0 support, covering **both sides** of
the SAML relationship in a single walkthrough:

- **Hearth as Service Provider (SP):** consumes a signed `<Response>`
  from an external Identity Provider, validates XML-DSIG + audience +
  destination + InResponseTo + replay.
- **Hearth as Identity Provider (IdP):** receives an `<AuthnRequest>`
  from an external SP, issues a signed `<Response>` back, verifiable
  against the cert in Hearth's published IdP metadata.

Unlike [`../federation-flow/`](../federation-flow/) (OIDC) and
[`../oauth-consent-flow/`](../oauth-consent-flow/) (OAuth2), this demo
does *not* spin up a full browser round-trip with a separate IdP
process. Standing up a real SAML IdP (Shibboleth / SimpleSAMLphp / Okta)
is a project in itself, so the demo takes a shortcut: **it impersonates
both the external IdP and the external SP directly from a Node script**,
using `xml-crypto` + `node-forge` to sign and verify SAML XML.

---

## What this example demonstrates

- **Metadata endpoints**: Hearth serves
  `SPSSODescriptor` at `/ui/realms/{realm}/federation/saml/metadata?idp=…`
  and `IDPSSODescriptor` at `/ui/realms/{realm}/saml/metadata`. The demo
  fetches both and pulls the signing cert out of the IdP metadata for
  downstream verification.
- **Assertion Consumer Service (ACS)**: the script generates a fresh
  RSA-2048 keypair + self-signed cert for the fake IdP, inlines the
  cert into `hearth.yaml` before boot, then signs an `<Assertion>` with
  that key and POSTs it to Hearth's ACS endpoint. Hearth verifies the
  signature, audience, destination, and `InResponseTo` against the
  `RelayState` it issued at `begin`.
- **Replay protection**: the same signed assertion is POSTed twice. The
  first succeeds; the second is rejected by the `saml:asn:*` sentinel.
- **IdP-issued Response**: the script flips roles, sends an
  `<AuthnRequest>` to Hearth's SSO endpoint pretending to be an
  external SP (registered in YAML as `demo-sp`), and receives back an
  auto-submitting HTML form carrying a signed `<samlp:Response>`. The
  script verifies that Response's `<ds:Signature>` against the cert it
  extracted from Hearth's IdP metadata in act 1.
- **Algorithm suite locked to RSA-SHA256 + SHA-256 + exclusive C14N**.
  SHA-1 and RSA-SHA1 are rejected server-side (algorithm-downgrade
  defense); the demo uses the accepted suite throughout.

---

## Prerequisites

- Rust toolchain (for `cargo build --release`).
- Node.js 18+.
- `python3` (used by `run.sh` to parse `cargo metadata` output).

The demo binds to `localhost:8420`. If that port is taken, edit
`hearth.yaml` and the three port references in `demo.mjs`.

---

## Run it

```bash
cd examples/saml-flow
./run.sh
```

On success you'll see three acts complete:

```
▸ Act 1 — fetch Hearth's SP metadata
✔ SP metadata served (1742 bytes)
  ACS URL: http://localhost:8420/ui/realms/demo/federation/saml/acs

▸ Act 2 — fake IdP issues a signed Response to Hearth's ACS
  RelayState token: …
  Expected InResponseTo: _h…
✔ ACS accepted signed assertion (HTTP 303)
  Redirect target: /ui/account
✔ replay rejected (HTTP 400)

▸ Act 3 — fake SP sends AuthnRequest to Hearth's IdP SSO
✔ fetched Hearth IdP metadata cert (1000 b64 chars)
✔ Hearth IdP produced auto-submit HTML form (5709 bytes)
✔ Hearth-signed Response verifies against Hearth's IdP cert
  Issuer: http://localhost:8420/ui/realms/demo
  NameID: placeholder@example.com

All three acts completed successfully.
```

After the demo exits, Hearth is torn down automatically. Audit events
for all three acts are visible if you boot Hearth manually against
`./hearth.yaml.rendered` and browse to `/ui/admin/audit`.

## Interop note

Building this demo turned into a useful interop exercise. The first run
failed on both sides of the round trip because Hearth's narrow
exclusive-C14N implementation differed from `xml-crypto`'s in two
specific ways: (1) which namespace decls got emitted at element
boundaries, and (2) how an extracted subtree should be canonicalized
when the relevant xmlns decl lives on an ancestor OUTSIDE the subtree.
Both issues were fixed as part of shipping this example — tracked in
the "known limitations" section of gap #6 and in
[`memory/saml.md`](../../memory/saml.md). The working round-trip with
`xml-crypto` is a real-world interop signal, not just Hearth
round-tripping its own output.

---

## Files

| File | Role |
|---|---|
| [`hearth.yaml`](./hearth.yaml) | Template config. `__IDP_CERT_PEM__` is a placeholder `run.sh` substitutes at boot with the freshly generated fake-IdP cert. |
| [`gen-idp-cert.mjs`](./gen-idp-cert.mjs) | Emits `.idp-cred.json` (private key + cert for the fake IdP side) and `.idp-cert.pem` (cert only, inlined into `hearth.yaml.rendered`). |
| [`demo.mjs`](./demo.mjs) | Three-act driver. Hand-rolls SAML XML, uses `xml-crypto` for signing + verification. |
| [`run.sh`](./run.sh) | Build + render + boot + drive + teardown. |

---

## Known shortcuts (phase-1 scope)

This demo reflects the known limitations of the phase-1 SAML
implementation (see `docs/gaps/FEATURE_GAPS.md` gap #6):

- **IdP-side Act 3 uses a placeholder NameID** (`placeholder@example.com`).
  Real deployments gate the IdP-side SSO endpoint on a live `UiSession`
  and emit the logged-in user's email — that plumbing is a follow-up PR.
- **No SLO.** The library ships `LogoutRequest` / `LogoutResponse`
  build + parse code and web route slots, but the fan-out wiring that
  actually revokes sessions is not yet connected. Acts 2 and 3 both
  produce audit events (`SamlLoginCompleted`, `SamlIdpResponseIssued`)
  but no session termination happens on either side.
- **No signed AuthnRequests on the outbound HTTP-Redirect binding.**
  The `sign_authn_requests: false` flag in `hearth.yaml` reflects this;
  IdPs that require signed requests won't interop yet.
- **Certificate parsing is a narrow DER walker, not a full X.509
  validator.** Cert chains, extensions, and revocation are out of scope;
  Hearth trusts the operator-supplied cert PEM verbatim.

For a checklist of what's still to do before enterprise GA, see
[`memory/saml.md`](../../memory/saml.md) (project-internal notes).
