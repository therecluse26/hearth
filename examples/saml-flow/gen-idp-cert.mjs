#!/usr/bin/env node
// Generates a throwaway RSA-2048 keypair + self-signed X.509 cert for
// the fake IdP. Invoked by run.sh before Hearth boots so the YAML can
// embed the cert PEM and Hearth's reconcile loop picks it up.
//
// Writes two artifacts next to this script:
//   .idp-cred.json  — { privateKeyPem, certificatePem } (demo.mjs reads this)
//   .idp-cert.pem   — cert only (run.sh inlines this into hearth.yaml)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import forge from "node-forge";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair({
  bits: 2048,
  e: 0x10001,
});
const cert = forge.pki.createCertificate();
cert.publicKey = publicKey;
cert.serialNumber = "01";
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
const attrs = [
  { name: "commonName", value: "saml-flow-demo-idp" },
  { name: "organizationName", value: "Hearth SAML Demo" },
];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(privateKey, forge.md.sha256.create());

const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
const certificatePem = forge.pki.certificateToPem(cert);

fs.writeFileSync(
  path.join(__dirname, ".idp-cred.json"),
  JSON.stringify({ privateKeyPem, certificatePem }, null, 2),
);
fs.writeFileSync(path.join(__dirname, ".idp-cert.pem"), certificatePem);
console.log("generated fake-IdP keypair + cert");
