# Streaming Sessions and Superseding Records

Long-running tasks can fill a record's `max_hops`, continue beyond its declared `expires_at`, or receive fresh human-approved context. HDP records those events; none is a reason for HDP to stop the task or condition an action.

## Recording depth and new records

`scope.max_hops` is the number of hops a token can hold. When its chain is full, it is not extended. The agent's next action may continue without another hop in that record. If more recording depth is needed, an issuer can create a superseding record with a new `token_id` and an empty chain.

```typescript
import {
  extendChain,
  generateKeyPair,
  issueToken,
  issueSupersedingToken,
} from "@helixar_ai/hdp";

const { privateKey } = await generateKeyPair();
const issued = await issueToken({
  sessionId: "sess-analysis-1",
  principal: { id: "analyst-42", id_type: "opaque" },
  scope: {
    intent: "Analyze the quarterly sales report",
    data_classification: "confidential",
    network_egress: false,
    persistence: false,
    max_hops: 1,
  },
  signingKey: privateKey,
  keyId: "issuer-key-v1",
});
const fullRecord = await extendChain(issued, {
  agent_id: "analysis-agent",
  agent_type: "sub-agent",
  action_summary: "Summarize the quarterly sales report",
  parent_hop: 0,
}, privateKey);

// The full record is not extended again. The application continues its task.
const successor = await issueSupersedingToken({
  original: fullRecord,
  scope: { ...fullRecord.scope, max_hops: 3 },
  signingKey: privateKey,
  keyId: "issuer-key-v1",
  expiresInMs: 60 * 60 * 1000,
});
console.log({
  token_id: successor.header.token_id,
  parentTokenId: successor.header.parent_token_id,
  chainLength: successor.chain.length,
});
```

`issueSupersedingToken()` sets `parent_token_id` before signing. The successor has new issuance and expiry timestamps, inherits the original session, principal, and scope unless overridden, and starts with an empty chain. The SDK uses a 24-hour fallback when `expiresInMs` is omitted; HDP defines no protocol default.

## Expiry is audit metadata

`expires_at` records the end of the period the principal declared at issuance. It must be greater than `issued_at`, but it does not affect integrity verification or stop a task. A hop at or after `expires_at` is recorded like any other and is reported by `auditToken()` as `recorded_after_period` with the hop sequence numbers.

If a principal makes a fresh approval or changes the declared context, a new linked record can preserve that update. This is an issuance and audit pattern, not an HDP runtime gate. Issuing a successor does not invalidate the earlier record or revoke it.

## Audit linked records

A `parent_token_id` identifies a linked record, but HDP v0.1 does not encode whether the relationship is supersession or joint approval. Auditors report `unknown` unless trusted application context supplies the relationship. To audit a task's history, retain all related tokens, trusted issuer public keys, and the context that identifies each link.

The original token remains a valid record of what its issuer signed. A hop added after its `expires_at` remains in that token and can still pass integrity verification; the audit report separately marks its recording period.
