import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as jose from "jose";
import { ensureBinary, startServer, stopServer, type TestServer } from "./helpers.js";

describe("TypeScript SDK: JWKS Validation", () => {
  let server: TestServer;

  beforeAll(async () => {
    ensureBinary();
    server = await startServer();
  });

  afterAll(() => {
    if (server) stopServer(server);
  });

  it("verifies token signatures using JWKS-fetched public keys", async () => {
    const { client, bootstrap } = server;

    // 1. Fetch the JWKS document
    const jwks = await client.jwks();
    expect(jwks.keys).toBeTruthy();
    expect(jwks.keys.length).toBeGreaterThan(0);

    // Verify the key is an Ed25519 (OKP) key
    const key = jwks.keys[0];
    expect(key.kty).toBe("OKP");
    expect(key.crv).toBe("Ed25519");
    expect(key.x).toBeTruthy();
    expect(key.alg).toBe("EdDSA");
    expect(key.use).toBe("sig");
    expect(key.kid).toBeTruthy();

    // 2. Import the public key for verification
    const publicKey = await jose.importJWK(key as jose.JWK, "EdDSA");

    // 3. The bootstrap access token is signed with the global key (same as /jwks)
    //    Verify it directly against the JWKS-fetched key
    const { payload: accessPayload } = await jose.jwtVerify(
      bootstrap.access_token,
      publicKey,
    );
    expect(accessPayload.sub).toBeTruthy();
    expect(accessPayload.exp).toBeTruthy();

    // 4. Verify the OIDC discovery document references the JWKS endpoint
    const discovery = await client.discovery();
    expect(discovery.jwks_uri).toBeTruthy();

    // 5. Verify the JWT header contains the correct kid and alg
    const header = jose.decodeProtectedHeader(bootstrap.access_token);
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe(key.kid);
    expect(header.typ).toBe("JWT");

    // 6. Verify a tampered token fails verification
    const tampered = bootstrap.access_token.slice(0, -4) + "XXXX";
    await expect(
      jose.jwtVerify(tampered, publicKey),
    ).rejects.toThrow();
  });
});
