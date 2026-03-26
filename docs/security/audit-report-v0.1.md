# HDP Reference Implementation — Security Audit Report

**Date:** 2026-03-26
**Scope:** src/crypto/, src/token/, src/chain/, src/privacy/

## Findings — PASS

### 12.1 Token Forgery
Tokens signed by an attacker key fail verification against the legitimate public key.
Root signature covers canonical JSON of header+principal+scope; any modification invalidates the signature.
Test: tests/security/token-forgery.test.ts

### 12.2 Prompt Injection via Natural Language Fields
SDK stores intent/action_summary/display_name as inert strings. No eval or execution path exists.
stripPrincipal() removes the entire principal section (including display_name) before transmission.
Test: tests/security/injection-fields.test.ts

### 12.3 Chain Tampering + Seq Gap Detection
Hash chain design: modifying any prior hop invalidates all subsequent hop signatures.
validateChain() enforces contiguous seq values starting at 1 — gaps are detected.
Tests: tests/security/chain-tampering.test.ts, tests/security/chain-poison.test.ts

### 12.7 Replay Attack (session mismatch)
verifyToken() checks session_id against currentSessionId before PoH verification step.
Test: tests/security/replay-attack.test.ts

### 12.7 Replay Attack (expiry)
verifyToken() checks expires_at at step 2. Expired tokens rejected regardless of signature validity.
Test: tests/security/replay-attack.test.ts

## Noted Gaps — Application Layer Concerns (out of scope for SDK)

- **12.4 Memory Poisoning:** Application must not store full tokens in unsecured memory stores. SDK does not persist tokens itself.
- **12.5 Goal Hijack via Scope Drift:** SDK stores scope.intent as an inert string. Semantic comparison of agent actions against intent is an application/security-layer concern.
- **12.6 Supply Chain:** Token issuance infrastructure must be hardened at deployment. SDK token signing is not a dynamically loaded module.
- **12.8 Confused Deputy:** SDK provides max_hops enforcement. Minimum-scope design at authorization time is an application design concern.
- **12.9 Adaptive Retry:** action_count constraints must be enforced by calling application. SDK provides the constraint structure but not enforcement.
- **12.10 Transport Security:** TLS enforcement is a deployment concern. SDK does not handle transport layer.

---

## Section 12 Threat Coverage Map

| Threat | Spec Ref | Test File | Coverage |
|---|---|---|---|
| Token Forgery | §12.1 | `tests/security/token-forgery.test.ts` | PASS — attacker-signed tokens fail against legitimate public key |
| Chain Tampering | §12.2 | `tests/security/chain-tampering.test.ts` | PASS — modifying any prior hop invalidates all subsequent hop signatures |
| Prompt Injection | §12.3 | `tests/security/injection-fields.test.ts` | PASS — SDK stores intent/action_summary as inert strings; no eval path |
| Seq Gap / Chain Poison | §12.3 (integrity) | `tests/security/chain-poison.test.ts` | PASS — validateChain() enforces contiguous seq values starting at 1 |
| Replay Attack (session) | §12.7 | `tests/security/replay-attack.test.ts` | PASS — verifyToken() checks session_id at step 6 |
| Replay Attack (expiry) | §12.7 | `tests/unit/verifier.test.ts` | PASS — verifyToken() checks expires_at at step 2 |
| Memory Poisoning | §12.4 | — | GAP — application must not store full tokens in unsecured memory stores |
| Goal Hijack / Scope Drift | §12.5 | — | GAP — SDK stores scope.intent as inert string; semantic comparison is application-layer |
| Supply Chain | §12.6 | — | GAP — token issuance infrastructure must be hardened at deployment |
| Confused Deputy | §12.8 | `tests/unit/chain-extender.test.ts` | PARTIAL — max_hops enforced; minimum-scope design at authorization time is application concern |
| Adaptive Retry | §12.9 | — | GAP — action_count constraints must be enforced by calling application |
| Transport Security | §12.10 | — | GAP — TLS enforcement is a deployment concern, not SDK concern |
| Offline Verification (liveness) | §12.7 (extended) | `tests/security/offline-verification.test.ts` | PASS — full chain verification requires zero network calls |

**Summary:** 7 threats directly tested (6 security tests + 1 unit test), 1 partial (max_hops), 4 application-layer gaps documented.
