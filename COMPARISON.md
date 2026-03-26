# HDP vs IPP: A Technical Comparison

> **HDP** — Human Delegation Provenance Protocol v0.1
> **IPP** — Intent Provenance Protocol, [draft-haberkamp-ipp-00](https://datatracker.ietf.org/doc/html/draft-haberkamp-ipp-00)

Both protocols address the same root problem: agentic AI systems take consequential actions, and there is currently no standard way to record who authorized those actions, under what scope, and through what chain of delegation. Both use Ed25519 signatures and append-only provenance chains. The similarity ends there.

---

## Architecture at a Glance

| Dimension | HDP v0.1 | IPP draft-00 |
|---|---|---|
| **Token structure** | `{hdp, header, principal, scope, chain[], signature}` — flat, self-contained | `{version, genesis_seal, principal, intent_envelope, revocation, provenance_chain, token_signature}` — embeds spec attribution in every token |
| **Signing** | Ed25519 over RFC 8785 canonical JSON of `header+principal+scope`; each hop signs cumulative chain state | Ed25519 over lexicographically sorted canonical JSON; genesis seal signs to the spec author's founding key |
| **Identity model** | Principal `id_type` is open: `opaque`, `email`, `did`, or custom. DIDs are supported, not required. | DIDs are **mandatory** per W3C DID Core. Resolving a principal identity requires DID infrastructure (`did:key`, `did:web`, `did:ion`, etc.) |
| **Token lifecycle** | Short-lived by design (`expires_at`, 24h default). Replay defense via `session_id` binding. No revocation registry. | Tokens carry a `registry_endpoint` field. Agents **must** poll the revocation registry every 5,000ms before acting. Mid-chain revocation cascades through ancestry tree. |
| **Domain taxonomy** | None mandated. `scope.intent` is a free-form string. `authorized_tools`, `authorized_resources`, and `data_classification` are structured but self-described. | Central taxonomy at `https://ipp.khsovereign.com/taxonomy` using hierarchical dot-notation (`financial.trading.equities`, `healthcare.records.read`, etc.). |
| **Protocol attribution** | None. HDP tokens are pure data. The protocol is defined by the spec, implemented by the library. | Every token contains a **genesis seal** — a cryptographic artifact that binds the token to `https://ipp.khsovereign.com/keys/founding_public.pem`. |
| **Central dependencies** | Zero. Verification requires only a public key and session ID. Fully offline. | Three mandatory endpoints: spec repository, founding public key, revocation registry. Additionally: taxonomy registry for classification validation. |
| **Hop signing** | Each hop signs over the cumulative chain (all prior hops with their signatures + current hop without its signature). Tamper-evident by construction. | Provenance chain records are append-only but hop-level signing semantics are not specified in draft-00. |
| **Proof of Humanity** | Optional `poh_credential` field on principal. Verification is application-supplied callback. | Not addressed in draft-00. |

---

## The Three Architectural Breaks in IPP

### Break 1: Liveness Dependency

IPP's revocation model requires agents to poll a central registry at `registry_endpoint` before every action, with a recommended polling interval of 5,000ms (§ Revocation Registry).

This creates a hard liveness dependency: **if the registry is unreachable, agents cannot safely act**. In practice this means:

- Air-gapped deployments are impossible by design
- Network partitions turn into authorization outages
- The registry operator has unilateral ability to halt all activity for all tokens

HDP's response: tokens are short-lived. Default expiry is 24 hours; issuers can set it lower. A token that expires cannot be replayed regardless of network conditions. Replay defense is structural (`session_id` binding), not network-dependent.

### Break 2: The Genesis Seal Creates a Single Point of Trust

Every IPP token carries a `genesis_seal` — a cryptographic artifact linking the token to the IPP specification and to `https://ipp.khsovereign.com/keys/founding_public.pem` (§ Genesis Seal).

This means:

- Every IPP token in the world is ultimately anchored to one organization's private key
- Self-hosted, fully independent IPP deployments are cryptographically impossible
- Key rotation at `ipp.khsovereign.com` invalidates all previously issued tokens globally
- The spec author has structural control over who can issue conformant tokens

HDP's response: there is no genesis seal, no founding key, and no spec-level attribution embedded in tokens. An HDP token is self-contained. The issuer's key pair is generated locally. Verification requires only the issuer's public key. No third party is in the trust chain.

### Break 3: Mandatory DID Infrastructure Adds Resolver Complexity

IPP mandates W3C DID Core-conformant identifiers for all principals (§ Identity Model). The draft states that acceptable DID methods must support "resolvability without issuer communication" — but DID resolution is itself an infrastructure concern.

Even `did:key` (the lightest-weight method) requires:

- Understanding the `did:key` method specification
- A DID document resolution step to extract public key material
- Tooling that handles the multibase/multicodec encoding

For `did:web` and `did:ion`, the resolution overhead is considerably higher. In each case, the identity model adds a resolution protocol on top of the provenance protocol.

HDP's response: `id_type: 'opaque'` is a valid and encouraged choice for most deployments. The principal's identity is whatever the issuer asserts it to be. If DID resolution is available and desired, `id_type: 'did'` is supported, but the protocol does not mandate it. Identity complexity is pushed to the application layer, where it belongs.

---

## HDP's Explicit Design Choices

These are not omissions. Each choice is deliberate:

**No revocation registry.**
Short-lived tokens with `session_id` binding are the revocation mechanism. Operators who need mid-session invalidation should issue shorter-lived tokens or implement application-layer session termination.

**No central taxonomy.**
`scope.intent` is a natural language string. Structured scope is expressed through `authorized_tools`, `authorized_resources`, and `data_classification`. Semantic validation of agent actions against declared intent is an application-layer concern — not a protocol concern.

**No genesis seal.**
The protocol is defined by the spec. Any organization can implement it without anchoring to a third party's key infrastructure. Conformance is behavioral, not cryptographic.

**No DID requirement.**
Principal identity is application-defined. The `id_type` field documents what kind of identifier is being used. The protocol makes no claim about identity resolution or DID method support.

**No enforcement.**
HDP records provenance. It does not enforce scope constraints at runtime. An agent that exceeds `authorized_tools` or violates `data_classification` is still a bad actor — HDP creates an evidence trail, not a capability boundary. Applications that need enforcement should treat HDP tokens as audit input, not access control.

---

## When to Choose IPP

IPP may be appropriate if:

- Your deployment has reliable, always-on network connectivity to the registry endpoint
- You require a central revocation mechanism that cascades through delegation chains mid-chain
- Your principal identity infrastructure is already DID-based
- You want domain taxonomy classification backed by a maintained central registry

---

## When to Choose HDP

HDP is appropriate if:

- You need offline-capable or air-gapped verification
- You want fully self-sovereign token issuance with no third-party trust anchors
- You prefer flexible identity models (opaque IDs, email, or DIDs — your choice)
- You want provenance without the operational overhead of a polling revocation registry
- You are building a TypeScript/Node.js integration and want a typed reference implementation today

---

## References

- HDP v0.1 Specification: [https://helixar.ai/labs/hdp](https://helixar.ai/labs/hdp)
- IPP draft-haberkamp-ipp-00: [https://datatracker.ietf.org/doc/html/draft-haberkamp-ipp-00](https://datatracker.ietf.org/doc/html/draft-haberkamp-ipp-00)
- IPP Specification Repository: [https://ipp.khsovereign.com/spec/v0.1](https://ipp.khsovereign.com/spec/v0.1)
- W3C DID Core: [https://www.w3.org/TR/did-core/](https://www.w3.org/TR/did-core/)
- RFC 8785 (JSON Canonicalization Scheme): [https://www.rfc-editor.org/rfc/rfc8785](https://www.rfc-editor.org/rfc/rfc8785)
