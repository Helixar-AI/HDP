# HDP Key Management Guide

## The Problem

HDP tokens are Ed25519-signed. Verifiers need the issuer's public key. Deployments without existing PKI infrastructure, such as a CA or certificate chain, need a lightweight pattern for distributing and resolving public keys.

## The `kid` Field

Every HDP token signature includes a `kid` (key ID) field:

```json
{
  "signature": {
    "alg": "Ed25519",
    "kid": "alice-signing-key-v1",
    "value": "..."
  }
}
```

`kid` is an opaque string chosen by the issuer. Verifiers use it to look up the correct public key. This is the only key-resolution primitive HDP requires.

## Option 1: Pre-provisioned Keys (Recommended for Air-Gapped or Simple Deployments)

Generate a key pair once, store the public key in config or a secrets manager, distribute it to verifiers at deploy time.

```typescript
import { exportPublicKey, generateKeyPair, importPublicKey, issueToken, verifyToken } from '@helixar_ai/hdp'

// Issuer: generate once and store securely
const { privateKey, publicKey: issuerPublicKey } = await generateKeyPair()
const exportedPub = exportPublicKey(issuerPublicKey)
// Store privateKey in secrets manager (AWS Secrets Manager, Vault, etc.)
// Distribute exportedPub to all verifiers out-of-band
const token = await issueToken({
  sessionId: 'sess-key-example',
  principal: { id: 'user-42', id_type: 'opaque' },
  scope: {
    intent: 'Prepare a report',
    data_classification: 'internal',
    network_egress: false,
    persistence: false,
  },
  signingKey: privateKey,
  keyId: 'alice-signing-key-v1',
})

// Verifier: import the trusted issuer key and verify the archived record
const publicKey = importPublicKey(exportedPub)
const result = await verifyToken(token, { publicKey })
if (!result.valid) {
  console.log({ token_id: token.header.token_id, failedStep: result.failedStep, errorCode: result.error.code })
}
```

## Option 2: Well-Known Endpoint (Recommended for Multi-Service Deployments)

Serve public keys at `/.well-known/hdp-keys.json`. Verifiers fetch once at startup and cache. No polling required — keys change only on rotation.

```typescript
import { KeyRegistry, auditToken, generateKeyPair, issueToken } from '@helixar_ai/hdp'

// Issuer: publish a well-known document containing the public key
const issuerRegistry = new KeyRegistry()
const { privateKey, publicKey: issuerPublicKey } = await generateKeyPair()
issuerRegistry.register('alice-key-v1', issuerPublicKey)
const doc = issuerRegistry.exportWellKnown()

// Verifier: load the document and audit the token record
const verifierRegistry = new KeyRegistry()
verifierRegistry.loadWellKnown(doc)
const token = await issueToken({
  sessionId: 'sess-key-example',
  principal: { id: 'user-42', id_type: 'opaque' },
  scope: {
    intent: 'Prepare a report',
    data_classification: 'internal',
    network_egress: false,
    persistence: false,
  },
  signingKey: privateKey,
  keyId: 'alice-key-v1',
})

// Resolve kid for offline integrity verification
const kid = token.signature.kid
const publicKey = verifierRegistry.resolve(kid)
const report = await auditToken(token, publicKey ? { publicKey } : {})
```

`KeyRegistry.revoke(kid)` removes a key from that registry. It does not revoke tokens. Keep archived public keys available for as long as historical records need integrity verification. If the issuer key is unavailable, `auditToken()` reports integrity as `unverified`; it does not make an action decision.

Well-known document format:

```json
{
  "keys": [
    { "kid": "alice-key-v1", "alg": "Ed25519", "pub": "<base64url>" }
  ]
}
```

## Option 3: DID Identifiers (Application-Defined Resolution)

The `principal.id_type` value `did` records that the principal identifier is a DID. HDP does not define DID resolution, and the SDK does not resolve a DID to an issuer key. An application may use its own DID method and trust rules to provision a public key.

```
did:key:z6Mk...  →  Ed25519 public key (multibase/multicodec encoded)
```

The example shows one DID method's representation only. Setting `principal.id_type` to `did` does not bind the principal identifier to the signing key.

## Key Rotation

1. Generate a new key pair with a new `kid` (e.g. `alice-key-v2`)
2. Add the new key to the well-known document alongside the old key
3. Begin issuing new tokens with the new `kid`
4. After issuance with the old `kid` stops, remove it from active key discovery when appropriate; retain the key in an authenticated archive for as long as historical audit requires
5. Never reuse a `kid` for a different key

## Production Checklist

- [ ] Private keys stored in a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault)
- [ ] Public keys served at `/.well-known/hdp-keys.json` or pre-provisioned in verifier config
- [ ] Key rotation plan documented (new `kid` on rotation, old key retained for the audit retention period)
- [ ] `expires_at` records the issuer-declared authorization period; audit reports hops at or after it without changing integrity verification
