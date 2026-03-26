# HDP Key Management Guide

## The Problem

HDP tokens are Ed25519-signed. Verifiers need the issuer's public key. In environments without existing PKI infrastructure — no CA, no certificate chain — you need a lightweight pattern for distributing and resolving public keys.

## The `kid` Field

Every HDP token signature includes a `kid` (key ID) field:

```json
{
  "signature": {
    "alg": "Ed25519",
    "kid": "alice-signing-key-v1",
    "value": "...",
    "signed_fields": ["header", "principal", "scope"]
  }
}
```

`kid` is an opaque string chosen by the issuer. Verifiers use it to look up the correct public key. This is the only key-resolution primitive HDP requires.

## Option 1: Pre-provisioned Keys (Recommended for Air-Gapped / Simple Deployments)

Generate a key pair once, store the public key in config or a secrets manager, distribute it to verifiers at deploy time.

```typescript
import { generateKeyPair, exportPublicKey, importPublicKey } from '@helixar_ai/hdp'

// Issuer: generate once and store securely
const { privateKey, publicKey } = await generateKeyPair()
const exportedPub = exportPublicKey(publicKey) // base64url string — safe to store/share
// Store privateKey in secrets manager (AWS Secrets Manager, Vault, etc.)
// Distribute exportedPub to all verifiers out-of-band

// Verifier: load at startup
const publicKey = importPublicKey(storedBase64urlString)
const result = await verifyToken(token, { publicKey, currentSessionId })
```

## Option 2: Well-Known Endpoint (Recommended for Multi-Service Deployments)

Serve public keys at `/.well-known/hdp-keys.json`. Verifiers fetch once at startup and cache. No polling required — keys change only on rotation.

```typescript
import { KeyRegistry } from '@helixar_ai/hdp'

// Issuer: expose your public keys
const registry = new KeyRegistry()
registry.register('alice-key-v1', publicKey)
// Serve registry.exportWellKnown() at /.well-known/hdp-keys.json

// Verifier: load at startup
const registry = new KeyRegistry()
const doc = await fetch('https://issuer.example.com/.well-known/hdp-keys.json').then(r => r.json())
registry.loadWellKnown(doc)

// Resolve kid from token at verification time
const kid = token.signature.kid
const publicKey = registry.resolve(kid)
if (!publicKey) throw new Error(`Unknown key: ${kid}`)
const result = await verifyToken(token, { publicKey, currentSessionId })
```

Well-known document format:

```json
{
  "keys": [
    { "kid": "alice-key-v1", "alg": "Ed25519", "pub": "<base64url>" }
  ]
}
```

## Option 3: `did:key` (Zero Infrastructure)

For development or self-sovereign deployments, use `did:key` — the public key *is* the identifier. No endpoint needed.

```
did:key:z6Mk...  →  Ed25519 public key (multibase/multicodec encoded)
```

Set `principal.id_type: 'did'` and `principal.id: 'did:key:z6Mk...'` in the token. The verifier resolves the public key from the DID string directly, without any network call.

## Key Rotation

1. Generate a new key pair with a new `kid` (e.g. `alice-key-v2`)
2. Add it to your well-known document alongside the old key
3. Begin issuing new tokens with the new `kid`
4. Once all tokens issued with the old `kid` have expired, remove it from the well-known document
5. Never reuse a `kid` for a different key

## Production Checklist

- [ ] Private keys stored in a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault)
- [ ] Public keys served at `/.well-known/hdp-keys.json` or pre-provisioned in verifier config
- [ ] Key rotation plan documented (new `kid` on rotation, old key retained until all its tokens expire)
- [ ] Token expiry set short enough that key rotation completes before exposure window closes (recommend ≤ 4h for sensitive operations)
