# HDP Protocol Boundaries and Audit Semantics

HDP is a record-only provenance protocol. An HDP token is not an authorization protocol, capability, access token, or credential. A service must not grant, refuse, or condition an action on the token's presence, verification result, or contents. Missing or invalid records are audit findings; the service makes action decisions through its own access control mechanism.

The `scope` object records the principal's declaration at issuance. It does not grant authority or constrain an agent at runtime. In HDP v0.1, the issuer signs the root and every hop, so a hop signature establishes what the issuer recorded. It does not prove that the named agent consented to the delegation or performed the described action.

## Integrity Verification

Input validation under draft Section 3 precedes the five integrity steps. The TypeScript `verifyToken(token, { publicKey })` API reports input-validation failures as `failedStep: 0`, then runs the following checks in order and stops at the first failure:

1. **Version:** `hdp` is recognized and equals `header.version`.
2. **Root signature:** the Ed25519 signature verifies over the canonical issuance record.
3. **Hop structure:** `seq` values are contiguous, each `parent_hop` refers to the root or a prior hop, and timestamps do not decrease.
4. **Hop signatures:** each recorded hop signature verifies in chain order.
5. **Recorded depth:** when `scope.max_hops` is present, the chain length does not exceed it.

The result is `{ valid: true }` or `{ valid: false, failedStep, error }`. Integrity verification needs the token and issuer public key only. It is independent of current time, session, presenter, and verifier-local token state. For serialized JSON input, the verifier rejects duplicate object members during input validation. For parsed object input, duplicate-member detection rests with the parser that produced the object.

## Audit Results

`auditToken()` reports audit fields separately from token integrity:

| Field | Meaning |
|---|---|
| `integrity` | `valid`, `invalid` with `failedStep` and error, or `unverified` when no public key is supplied. |
| `recordingPeriod` | `within_period`, `recorded_after_period` with hop sequence numbers, or `not_checked` for invalid input. |
| `session` | Optional comparison with `sessionId`; a mismatch does not make the record invalid. |
| `linkedRecords` | `none`, or a parent link with `supersession`, `joint_approval`, or `unknown` relationship. |
| `poh` | Optional application-defined Proof-of-Humanity result, separate from integrity. |

`expires_at` is required to be greater than `issued_at`, as an input-validation rule. It has no effect on integrity verification or an action. A hop whose timestamp is at or after `expires_at` remains in the chain and is reported as `recorded_after_period`.

Where an audit concerns a particular session, the caller can supply `sessionId`. A mismatch is an audit finding only. Likewise, a parent link does not identify its relationship by itself. Supply `linkedRecordRelationship` only when trusted application context establishes the link's meaning; otherwise the report uses `unknown`. Proof-of-Humanity verification, when configured, is also reported separately.

## Chain Integrity Is Not Completeness

Each hop protects the prefix through that hop. Removing trailing hops can leave a shorter prefix whose signatures still verify. Concurrent extensions can also produce different valid branches. Verification authenticates the record received; it cannot discover another branch or prove the supplied branch is final. Auditors that need evidence of an observed or settled snapshot can retain an authenticated receipt bound to the complete token digest.

An application may compare an authenticated transport identity with the final hop's `agent_id` as a separate attribution finding. Such a comparison does not change integrity verification and does not decide whether an action proceeds.

## Attribution and Scope Findings

When an agent holds several tokens, the application should bind each action or attempt to the record that actually triggered it. If attribution is uncertain, preserve that uncertainty in audit data.

Out-of-scope attempts and observed violations may be recorded in `action_summary`, with intended, attempted, blocked, and observed activity distinguished where it affects interpretation. Recording a finding does not change the scope or imply principal approval. Middleware adapters continue the underlying action when a tool or classification finding is recorded; recording failures do not abort that action.

The `authorized_tools` and `authorized_resources` fields are independent lists. HDP v0.1 defines no per-tool resource binding. Record any required relationship in `intent` and implement action controls in the service's own access-control mechanism.

## Recording Depth

`scope.max_hops` is the number of hops the record holds. Once the chain is full, it is not extended. An adapter skips the additional recording and lets the action proceed; accountability for off-record delegation rests with the agent that appended the last recorded hop. A chain longer than `max_hops` fails integrity step 5.

An issuer may create a superseding record when recording needs to continue or when a principal approves changed context. Supersession adds a record, starts with an empty chain, and does not invalidate the original. `expires_at` does not force a new record or stop a task; it marks the authorization period for later audit.

## Token References

Token stores treat every reference as an immutable snapshot. A UUID reference identifies the first complete canonical token stored under that token ID and must not become a mutable pointer to a longer chain. Later snapshots use content-addressed references of the form `sha256:<base64url-digest>`.

Resolution checks validate the UUID identity or digest of the complete RFC 8785 canonical token, including root and hop signatures. Reference resolution and HDP integrity verification establish which record was supplied; neither is an input to the service's decision to act.
