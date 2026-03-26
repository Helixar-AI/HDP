# Streaming Sessions and Scope Evolution

## The Problem

Long-running agentic sessions present a challenge: the initial scope may be too narrow by the time the task is underway, `max_hops` may be exhausted before the task completes, or a new high-risk action emerges that requires fresh human approval.

HDP's answer is **re-authorization**: each scope change is a new human authorization event, producing a new token that references its predecessor.

## Core Principle

> Scope evolution must be explicit and human-initiated.

Implicit scope expansion — an agent quietly acquiring new capabilities mid-session — is precisely the failure mode HDP is designed to make visible. The `parent_token_id` chain creates an auditable record of every scope change: who approved it, when, and what changed.

## The Re-Authorization Pattern

```typescript
import { issueReAuthToken } from '@helixar_ai/hdp'

// Phase 1: initial authorization
const token = await issueToken({ ..., scope: { intent: 'analyze Q1', max_hops: 2 } })

// ... agents work, max_hops exhausted ...

// Phase 2: human approves scope expansion — system calls issueReAuthToken
const reAuthToken = await issueReAuthToken({
  original: token,               // parent_token_id set automatically
  scope: {
    intent: 'analyze Q1 + Q2',  // expanded intent
    max_hops: 3,                  // fresh hop budget
    data_classification: 'confidential',
    network_egress: false,
    persistence: false,
  },
  signingKey: issuerPrivateKey,
  keyId: 'issuer-key-v1',
})

// reAuthToken.header.parent_token_id === token.header.token_id ✓
// reAuthToken.chain === [] (fresh chain, hop counter resets)
```

The re-auth token:
- Gets a new `token_id`, `issued_at`, and `expires_at`
- Records `parent_token_id` pointing to the superseded token
- Inherits `scope`, `principal`, and `session_id` from the original (all overridable)
- Starts with an empty chain — the hop counter resets

## When to Re-Authorize

| Trigger | Action |
|---|---|
| `max_hops` exhausted | Re-authorize with a new hop budget |
| Task scope has expanded | Re-authorize with updated `intent`, `authorized_tools`, or `authorized_resources` |
| Token approaching expiry | Re-authorize with a fresh `expires_at` |
| High-risk action emerged | Re-authorize; the human explicitly reviews and approves the new action |
| Session handoff | Re-authorize with updated `session_id` if session is rotating |

## Token Lifetime Guidance

Short-lived tokens are the revocation mechanism. Do not issue long-lived tokens and rely on re-authorization to compensate.

| Session type | Recommended `expiresInMs` |
|---|---|
| Interactive / human-in-loop | 1–4 hours |
| Batch / overnight job | 8–12 hours |
| Continuous pipeline | 1 hour; re-authorize automatically at each phase |
| High-risk action | 15–30 minutes |

## Auditing the Re-Authorization Chain

To reconstruct the full authorization history of a session, collect all tokens with the same `header.session_id` and walk the `parent_token_id` links:

```
T1 (original, max_hops: 2)
  └─ T2 (re-auth, parent_token_id: T1, scope expanded)
       └─ T3 (re-auth, parent_token_id: T2, high-risk approval)
```

Each link is a signed human decision. Verifiers who need the full history verify each token independently.

## What Re-Authorization Is Not

- **Not a mutable token.** The original token is never modified. It remains valid until its `expires_at`.
- **Not automatic.** `issueReAuthToken` must be called by the system that obtained the human's approval. The agent cannot re-authorize itself.
- **Not a capability grant.** Re-authorization records that a human approved an expanded scope; it does not enforce that scope at runtime.
