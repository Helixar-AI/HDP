# Multi-Principal Delegation

## The Problem

Some actions are too consequential for a single human to authorize alone. Regulated industries (finance, healthcare, critical infrastructure) commonly require joint authorization — two people who must both approve before a high-risk action is taken.

HDP v0.1 supports one `principal` per token. Multi-principal authorization uses **sequential token chaining**.

## The Pattern: Sequential Token Chaining

Human A issues token T1. Human B reviews T1, agrees, and issues T2 with `parent_token_id: T1.token_id`. Any verifier that needs both humans' authorization walks the chain and verifies both.

```typescript
import { issueToken, issueReAuthToken, verifyPrincipalChain } from '@helixar_ai/hdp'

// Human A authorizes
const t1 = await issueToken({
  sessionId: 'sess-joint-auth',
  principal: { id: 'alice', id_type: 'opaque', display_name: 'Alice (CFO)' },
  scope: { intent: 'Approve $2M wire transfer to Acme Corp', data_classification: 'confidential', network_egress: true, persistence: true },
  signingKey: alicePrivateKey, keyId: 'alice-key-v1',
})

// Human B reviews T1 and co-authorizes
const t2 = await issueReAuthToken({
  original: t1,
  principal: { id: 'bob', id_type: 'opaque', display_name: 'Bob (CEO)' },
  signingKey: bobPrivateKey, keyId: 'bob-key-v1',
})
// t2.header.parent_token_id === t1.header.token_id ✓

// Verifier checks both humans authorized
const result = await verifyPrincipalChain(
  [
    { token: t1, publicKey: alicePublicKey },
    { token: t2, publicKey: bobPublicKey },
  ],
  { currentSessionId: 'sess-joint-auth' }
)

if (!result.valid) {
  throw new Error(`Joint authorization failed at token ${result.failedAt}: ${result.error?.message}`)
}
// Both Alice and Bob have signed ✓ — proceed with action
```

## What verifyPrincipalChain Validates

1. Each token passes full 7-step verification (root signature, hop signatures, expiry, session_id)
2. `parent_token_id` links are correct: `T[i].parent_token_id === T[i-1].token_id`
3. All tokens share the same `session_id`

## Properties of This Approach

**Audit trail.** Each human's authorization is a separately signed artifact. Neither can deny having authorized.

**Sequential, not simultaneous.** Human B sees exactly what Human A signed before co-signing. This is a feature: B is confirming A's authorization, not independently authorizing the same thing.

**Key independence.** Alice and Bob have separate key pairs. Compromise of one key does not compromise the other's authorization.

**Compatible with existing infrastructure.** No threshold cryptography required. Works with any standard Ed25519 key pair.

## Depth: Three or More Principals

Extend the same pattern: T3 has `parent_token_id: T2`, T2 has `parent_token_id: T1`. Pass all three to `verifyPrincipalChain` in order.

## v0.2 Preview: Simultaneous Co-Authorization

Sequential chaining requires B to act after A. For simultaneous joint authorization (both humans sign at the same time without seeing each other's signature first), a threshold signing scheme is needed.

HDP v0.2 will introduce `CoAuthorizationRequest` with a `threshold` field and `co_signatures` array, backed by FROST or Schnorr multisig. The `CoAuthorizationRequest` type is available in the SDK today as a type-only preview:

```typescript
import type { CoAuthorizationRequest } from '@helixar_ai/hdp'
// threshold: 2, co_signatures: [aliceSig, bobSig]
// Signing pipeline: planned for v0.2
```
