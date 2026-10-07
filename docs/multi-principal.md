# Joint Approval by Several Principals

HDP v0.1 records one principal per token. To record a joint approval, each principal's approval is a separately signed token. A later token may set `header.parent_token_id` to the previous token's `token_id`, and the linked records share a `session_id`.

The parent link does not say whether a record supersedes its parent or records another principal's approval. Auditors report the relationship as `unknown` without trusted application context that identifies the link as joint approval. Expiry, principal equality, and session equality alone do not establish that relationship.

## Create and audit linked records

`issueSupersedingToken()` creates a new token with a signed `parent_token_id` link. The application retains the context that identifies the link as joint approval; the token does not carry a relationship type.

```typescript
import {
  generateKeyPair,
  issueToken,
  issueSupersedingToken,
  verifyPrincipalChain,
} from "@helixar_ai/hdp";

const aliceKeys = await generateKeyPair();
const bobKeys = await generateKeyPair();
const scope = {
  intent: "Review the quarterly report",
  data_classification: "confidential" as const,
  network_egress: false,
  persistence: false,
};

const first = await issueToken({
  sessionId: "sess-quarterly-review",
  principal: { id: "alice", id_type: "opaque" },
  scope,
  signingKey: aliceKeys.privateKey,
  keyId: "alice-key-v1",
});
const second = await issueSupersedingToken({
  original: first,
  principal: { id: "bob", id_type: "opaque" },
  signingKey: bobKeys.privateKey,
  keyId: "bob-key-v1",
});
const entries = [
  { token: first, publicKey: aliceKeys.publicKey },
  { token: second, publicKey: bobKeys.publicKey },
];

const withoutContext = await verifyPrincipalChain(entries);
console.log({ token_id: second.header.token_id, relationship: withoutContext.relationship });

// Supply this only when trusted application records establish joint approval.
const withContext = await verifyPrincipalChain(entries, {
  relationshipContext: { type: "joint_approval", authenticated: true },
});
console.log({
  token_id: second.header.token_id,
  recordsValid: withContext.valid,
  relationship: withContext.relationship,
});
```

Without the authenticated context, the relationship is `unknown`, even when all signatures, parent links, and session IDs match. With the context, `relationship` is `joint_approval` when the chain contains more than one valid, linked record. `valid` reports integrity and linkage checks; it is not an action decision.

## Verification requirements

`verifyPrincipalChain()` checks each token's integrity with the public key for that issuer, then checks parent linkage and shared session IDs. A failed token or relationship check returns `valid: false`, `failedAt`, and an error. The helper does not decide whether an application should perform an action.

Applications must retain authenticated context that labels each parent-child relationship as joint approval, such as an integrity-protected issuance record bound to the tokens' issuers and root signatures. Without that context, auditors report the relationship as `unknown`. A superseding token may use a different session ID; tokens recorded as one joint-approval chain must share a session ID.

## Composition

An application may instead retain independent tokens and an authenticated receipt binding their digests to the task. Whether linked or composed, the application context supplies the meaning of the approvals.

## Simultaneous signatures

`CoAuthorizationRequest` is an exported type-only v0.2 preview. Threshold signing is not implemented in HDP v0.1.
