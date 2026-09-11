# HDP Protocol Boundaries and Audit Semantics

HDP is a provenance protocol. It carries a signed record of the delegation context declared at issuance and the agent activity subsequently recorded in the chain. It is not an access token, capability, or credential, and passing HDP verification does not authorize a request.

In HDP v0.1, the issuer signs the root and every hop. A hop signature therefore establishes what the issuer recorded. It does not prove that the named agent signed, consented to the delegation, knew about the record, or performed the described action.

## Three Different Audit Questions

Keep these results separate:

| Question | Meaning |
|---|---|
| Record integrity | Do the structure, version, root signature, chain rules, hop signatures, and declared delegation budget verify? Expiry and revocation do not change the signature mathematics. |
| Current acceptance | Does the complete live pipeline pass now, including issuance/expiry time, local revocation state, session binding, and any configured application checks? |
| Historical acceptance | Is there authenticated evidence that a named verifier accepted this exact token for a particular session, request, and time under the revocation and policy state then in force? |

Missing historical evidence is an indeterminate result, not evidence of acceptance. A useful verifier receipt binds at least the complete canonical token digest, request or event, session identifier, verifier identity, evaluation time, decision, and relevant revocation and policy state.

## Offline Verification and Revocation

Live verification needs only locally available inputs: a trusted issuer public key, the expected session identifier, current time, and the verifier's revocation state. No central registry or network call is required.

Verifiers must support local revocation by `header.token_id`. HDP deliberately leaves the authorization, distribution, freshness, and retention of revocation instructions to verifier policy. Re-authorization does not revoke an older token; it creates a new signed record linked through `parent_token_id`.

## Chain Integrity Is Not Completeness

Each hop protects the prefix through that hop. Removing trailing hops leaves a shorter prefix whose signatures may still verify. Concurrent extensions can also produce different, equally valid branches with the same token ID, hop count, and final agent ID. The verification pipeline authenticates the branch it receives; it cannot discover another branch or prove that the supplied branch is final.

Where the transport authenticates the caller, applications should compare that identity with the final hop's `agent_id`. This catches some stale-prefix presentations but does not solve completeness. Deployments that require one linear history should serialize extension at the issuer and atomically reject stale prefixes. Audits that need evidence of an observed or settled snapshot should retain an authenticated receipt bound to the complete token digest, not only a hop count.

## Attribution and Violations

When an agent holds several tokens, the application must bind each action or attempt to the task and token that actually triggered it. It must not select another token merely because that token's scope would make the action look permitted. If attribution is uncertain, preserve that uncertainty.

Record out-of-scope attempts, blocked actions, and violations under the triggering token, with `action_summary` clearly distinguishing intended, attempted, blocked, and observed activity. Recording a violation does not change the scope or imply principal approval.

The `authorized_tools` and `authorized_resources` fields are independent lists. HDP v0.1 defines no per-tool resource binding. Put any required relationship in `intent` or enforce it in a separate authorization policy.

## Delegation Budgets

`scope.max_hops` records an issuer-selected delegation budget; it is not a protocol-wide limit. A hard budget can encourage off-record delegation once the chain is full. Omit it unless the human-declared budget has evidentiary value, and make re-authorization easy when a recorded task legitimately needs more hops. Verifiers may also impose their own local chain-length policy.

## Token References

Token stores must treat every reference as an immutable snapshot. A UUID reference identifies the first complete canonical token stored under that token ID and must never become a mutable pointer to a longer chain. Later snapshots use content-addressed references of the form `sha256:<base64url-digest>`.

Resolution must validate either the UUID identity or the digest of the complete RFC 8785 canonical token, including its root and hop signatures. Reference integrity and HDP signature verification are separate checks; both are required before live use or an audit conclusion.
