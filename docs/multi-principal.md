# Multi-Principal Delegation

## The Problem

Some actions are too consequential for a single human to authorize alone. Regulated industries (finance, healthcare, critical infrastructure) commonly require joint authorization — two people who must both approve before a high-risk action is taken.

HDP v0.1 supports one `principal` per token. One way to record multi-principal authorization is **sequential token chaining**.

## The Pattern: Sequential Token Chaining

Human A issues token T1. Human B reviews T1 and issues T2 with `parent_token_id: T1.token_id`. Any verifier whose policy requires both records walks the chain and verifies both. The parent link alone does not say whether T2 supersedes T1 or joins it; trusted application context must record that relationship.

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

// Verifier checks both signed records and their parent/session linkage.
// Application policy separately establishes that the relationship is joint authorization.
const result = await verifyPrincipalChain(
  [
    { token: t1, publicKey: alicePublicKey },
    { token: t2, publicKey: bobPublicKey },
  ],
  {
    currentSessionId: 'sess-joint-auth',
    relationshipContext: { type: 'joint_authorization', authenticated: true },
  }
)

if (!result.valid) {
  throw new Error(`Joint authorization failed at token ${result.failedAt}: ${result.error?.message}`)
}
// Both issuer records verify ✓ — the service still applies its own authorization policy
// result.relationship === 'joint_authorization'
```

## What verifyPrincipalChain Validates

1. Each token passes live verification, or historical integrity verification when auditing past records
2. `parent_token_id` links are correct: `T[i].parent_token_id === T[i-1].token_id`
3. All tokens share the same `session_id`

The application must additionally retain authenticated context that labels each parent-child relationship as joint authorization. Without it, an auditor can establish only that the records are linked, not what the link meant.

## Properties of This Approach

**Audit trail.** Each issuer's statement is a separately signed artifact. The signature authenticates that statement; it does not by itself prove the human interaction or the action later taken.

**Sequential, not simultaneous.** Human B can review what Human A's token records before issuing T2. Whether B confirms A's authorization, supersedes it, or establishes another relationship must come from retained application context.

**Key independence.** Alice and Bob have separate key pairs. Compromise of one key does not compromise the other's authorization.

**Compatible with existing infrastructure.** No threshold cryptography required. Works with any standard Ed25519 key pair.

## Depth: Three or More Principals

Extend the same pattern: T3 has `parent_token_id: T2`, T2 has `parent_token_id: T1`. Pass all three to `verifyPrincipalChain` in order.

## Composition as an Alternative

Applications may instead require multiple independent tokens to accompany one request. Composition is more flexible, while chaining signs the link between records. Either approach needs an authenticated receipt or policy record binding the relevant token digests to the request and stating why the records were combined.

## v0.2 Preview: Simultaneous Co-Authorization

Sequential chaining requires B to act after A. For simultaneous joint authorization (both humans sign at the same time without seeing each other's signature first), a threshold signing scheme is needed.

HDP v0.2 will introduce `CoAuthorizationRequest` with a `threshold` field and `co_signatures` array, backed by FROST or Schnorr multisig. The `CoAuthorizationRequest` type is available in the SDK today as a type-only preview:

```typescript
import type { CoAuthorizationRequest } from '@helixar_ai/hdp'
// threshold: 2, co_signatures: [aliceSig, bobSig]
// Signing pipeline: planned for v0.2
```
