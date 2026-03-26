<div align="center">

# HDP
### Human Delegation Provenance Protocol

**A cryptographic chain-of-custody protocol for agentic AI systems.**
*Every action an agent takes, traceable back to the human who authorized it.*

<br/>

[![npm version](https://img.shields.io/npm/v/@helixar_ai/hdp?style=flat-square&color=0ea5e9&label=npm)](https://www.npmjs.com/package/@helixar_ai/hdp)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg?style=flat-square)](https://creativecommons.org/licenses/by/4.0/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Tests](https://img.shields.io/github/actions/workflow/status/Helixar-AI/HDP/ci.yml?branch=main&style=flat-square&label=tests&logo=github)](https://github.com/Helixar-AI/HDP/actions)
[![Offline Verified](https://img.shields.io/badge/verification-fully%20offline-22c55e?style=flat-square)](https://github.com/Helixar-AI/HDP/blob/main/tests/security/offline-verification.test.ts)
[![Ed25519](https://img.shields.io/badge/crypto-Ed25519-7c3aed?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc8032)
[![MCP Ready](https://img.shields.io/badge/MCP-middleware%20included-f97316?style=flat-square)](./packages/hdp-mcp)

<br/>

```
Human ──signs──▶ Token ──delegates──▶ Agent A ──delegates──▶ Agent B ──delegates──▶ Agent C
                   │                     │                      │                      │
                   └── Ed25519 root sig  └── hop sig 1          └── hop sig 2          └── hop sig 3
                           │                    │                      │                      │
                           └────────────────────┴──────────────────────┴──────────────────────┘
                                              verified offline, no registry, no network
```

</div>

---

HDP captures, structures, cryptographically signs, and verifies the human delegation context in agentic AI systems. When a person authorizes an agent to act — and that agent delegates to another agent, and another — HDP creates a tamper-evident chain of custody from the authorizing human to every action taken on their behalf.

---

## Why Not IPP?

The [Intent Provenance Protocol](https://datatracker.ietf.org/doc/html/draft-haberkamp-ipp-00) (draft-haberkamp-ipp-00) solves the same problem with different trade-offs. The critical difference: **IPP requires agents to poll a central revocation registry every 5 seconds**. If the registry is unreachable, agents cannot safely act. Every IPP token is also cryptographically anchored to `ipp.khsovereign.com/keys/founding_public.pem` — making fully self-sovereign deployment impossible.

HDP verification is fully offline. It requires only a public key and a session ID. No registry. No central endpoint. No third-party trust anchor.

→ [Full technical comparison: COMPARISON.md](./COMPARISON.md)

---

## Install

```bash
npm install @helixar_ai/hdp
```

---

## Quickstart

Issue a token, extend it through a delegation chain, verify it — under 2 minutes.

```typescript
import { generateKeyPair, issueToken, extendChain, verifyToken } from '@helixar_ai/hdp'

// 1. Generate a key pair for the issuer
const { privateKey, publicKey } = await generateKeyPair()

// 2. Issue a token (the human authorization event)
let token = await issueToken({
  sessionId: 'sess-20260326-abc123',
  principal: {
    id: 'usr_alice_opaque',
    id_type: 'opaque',
    display_name: 'Alice Chen',
  },
  scope: {
    intent: 'Analyze Q1 sales data and generate a summary report.',
    authorized_tools: ['database_read', 'file_write'],
    authorized_resources: ['db://sales/q1-2026'],
    data_classification: 'confidential',
    network_egress: false,
    persistence: true,
    max_hops: 3,
  },
  signingKey: privateKey,
  keyId: 'alice-signing-key-v1',
})

// 3. Extend the chain as the task delegates to agents
token = await extendChain(token, {
  agent_id: 'orchestrator-v2',
  agent_type: 'orchestrator',
  action_summary: 'Decompose analysis task and delegate to sub-agents.',
  parent_hop: 0,
}, privateKey)

token = await extendChain(token, {
  agent_id: 'sql-agent-v1',
  agent_type: 'sub-agent',
  action_summary: 'Execute read query against sales database.',
  parent_hop: 1,
}, privateKey)

// 4. Verify at any point in the chain (fully offline)
const result = await verifyToken(token, {
  publicKey,
  currentSessionId: 'sess-20260326-abc123',
})

console.log(result.valid) // true
console.log(token.chain.length) // 2
```

---

## Privacy Utilities

HDP includes GDPR-oriented utilities for handling tokens before logging or MCP transmission:

```typescript
import { stripPrincipal, redactPii, buildAuditSafe } from '@helixar_ai/hdp'

// Remove all principal PII before sending token to an MCP agent
const safeForTransmission = stripPrincipal(token)

// Anonymize identity fields while preserving token structure
const anonymized = redactPii(token)
// → principal.id becomes '[REDACTED]', display_name removed

// Build a safe audit log entry (token_id + intent + chain summary, no PII)
const auditEntry = buildAuditSafe(token)
```

---

## Transport Helpers

```typescript
import { encodeHeader, decodeHeader, InMemoryTokenStore, storeToken, resolveToken } from '@helixar_ai/hdp'

// HTTP header transport (X-HDP-Token)
const headerValue = encodeHeader(token)         // base64url JSON
const recovered = decodeHeader(headerValue)      // HdpToken

// Token-by-reference (X-HDP-Token-Ref)
const store = new InMemoryTokenStore()
const tokenId = await storeToken(store, token)   // returns token_id
const retrieved = await resolveToken(store, tokenId)
```

---

## Verification Pipeline

`verifyToken()` runs a 7-step pipeline defined in HDP spec §7.3:

1. Version check
2. Expiry (`expires_at`)
3. Root signature (Ed25519 over header + principal + scope)
4. Hop signatures — **mandatory per §6.3 Rule 6** (each hop signs cumulative chain state)
5. `max_hops` constraint
6. Session ID binding (replay defense)
7. Proof-of-Humanity credential (optional, application-supplied callback)

Verification is **fully offline**. No registry lookup. No network call. Requires only the issuer's public key and the current session ID.

---

## Scope Boundary

**HDP stops at provenance. It does not enforce.**

HDP records that a human authorized an agent to act, with what scope, through what chain. It does not:

- Prevent an agent from exceeding its declared scope at runtime
- Enforce `authorized_tools` or `data_classification` constraints
- Make revocation decisions
- Provide a central authority

Applications that need runtime enforcement should treat HDP tokens as audit input and implement enforcement at the application layer.

---

## Security

HDP v0.1 has been audited against spec §12's 10 threat scenarios. See [docs/security/audit-report-v0.1.md](./docs/security/audit-report-v0.1.md).

Test coverage:
- Token forgery
- Chain tampering
- Prompt injection
- Seq gap / chain poisoning
- Replay attack (session + expiry)
- Offline verification guarantee

---

## Spec

Full protocol specification: [https://helixar.ai/labs/hdp](https://helixar.ai/labs/hdp)

---

## License

[CC BY 4.0](./LICENSE) — Helixar Limited
