# HDP Standardization Path

## The Situation

`draft-haberkamp-ipp-00` (Intent Provenance Protocol) is already in the IETF document stream. If it advances through working group adoption, it will become the reference point for agentic AI delegation protocols — regardless of its architectural trade-offs.

HDP's position must be formally documented in the standards record **before** IPP advances, not after. An IETF individual draft is the right vehicle. It is not a commitment to a long standardization process; it is a technical stake in the ground.

---

## Recommended Path: IETF Individual Draft

### Why IETF

- IPP is already there — the comparison must happen in the same venue
- IETF has the strongest track record for identity and security protocols (OAuth, JOSE, TLS, PKIX)
- Individual drafts can be filed by anyone; no working group sponsorship required to start
- IETF informational RFCs allow architectural position documents, not just protocol specifications

### Why Not W3C or OpenID Foundation

**W3C:** Focused on web standards and Verifiable Credentials. HDP is agentic-specific; it doesn't fit cleanly into the VC model. Engage W3C for feedback on the DID compatibility story, not as the primary venue.

**OpenID Foundation:** Strong enterprise identity community. Relevant for OIDC/OAuth2 integration patterns. A secondary venue for field feedback, not primary standardization.

---

## Filing an Individual Draft

### Step 1: Write the Draft

Individual drafts follow RFC format. The working title:

```
draft-helixar-hdp-agentic-delegation-00
```

Suggested structure:

```
1. Introduction
   1.1. Motivation
   1.2. Design Goals
   1.3. Relationship to IPP (draft-haberkamp-ipp-00)

2. Token Structure
   2.1. HdpToken Schema
   2.2. HdpHeader
   2.3. HdpPrincipal
   2.4. HdpScope
   2.5. HopRecord

3. Cryptographic Signing
   3.1. Root Signature (Ed25519 over RFC 8785 Canonical JSON)
   3.2. Hop Signature Chain
   3.3. Verification Pipeline (7 Steps)

4. Chain Extension Rules
   4.1. Sequence Integrity
   4.2. max_hops Enforcement
   4.3. Re-Authorization (parent_token_id)

5. Transport
   5.1. X-HDP-Token HTTP Header
   5.2. Token-by-Reference (X-HDP-Token-Ref)

6. Privacy Considerations
   6.1. Minimum-Disclosure Principal Fields
   6.2. GDPR Compliance Utilities

7. Security Considerations
   7.1. Threat Model (Section 12 of HDP v0.1 spec)
   7.2. Comparison with IPP Threat Model
   7.3. Offline Verification Guarantee

8. IANA Considerations
   8.1. HTTP Header Registration (X-HDP-Token)

9. Comparison with Related Work
   9.1. IPP (draft-haberkamp-ipp-00)
   9.2. OAuth 2.0 Token Exchange (RFC 8693)
   9.3. UCAN (User Controlled Authorization Networks)

10. References
```

Use the [IETF Author Tools](https://author.ietf.org/) to generate XML/RFC format from Markdown via `xml2rfc`.

### Step 2: Submit

1. Create an account at [datatracker.ietf.org](https://datatracker.ietf.org)
2. Upload the draft at [datatracker.ietf.org/submit](https://datatracker.ietf.org/submit/)
3. The draft becomes publicly visible within minutes
4. File as an individual submission (no working group required)

### Step 3: Announce

Post to relevant IETF mailing lists:

- `oauth@ietf.org` — token delegation patterns
- `rats@ietf.org` — attestation and trust chain practitioners
- `dispatch@ietf.org` — new work that doesn't yet have a home WG

Subject line template:
```
[ANNOUNCE] draft-helixar-hdp-agentic-delegation-00: Human Delegation Provenance for Agentic AI
```

---

## The Comparison Section Is Non-Optional

The draft's comparison with IPP (Section 9.1 above) must be technically precise and non-adversarial. IETF culture values architectural clarity over competitive positioning. The framing:

> IPP (draft-haberkamp-ipp-00) and HDP address the same problem with different trade-offs. The key architectural differences are:
>
> 1. **Revocation model:** IPP requires polling a central registry (§ Revocation Registry). HDP uses short-lived tokens with session_id binding; no registry lookup is required.
>
> 2. **Trust anchor:** IPP embeds a genesis seal linking every token to the spec author's public key. HDP tokens are self-contained; verification requires only the issuer's public key.
>
> 3. **Identity model:** IPP mandates W3C DID Core. HDP supports opaque IDs, email, DIDs, and custom id_type values. DID resolution infrastructure is optional.
>
> These are design choices, not defects. Deployments with reliable connectivity to a central registry, existing DID infrastructure, and a requirement for mid-chain revocation may prefer IPP.

---

## Working Group Strategy

There is currently no IETF working group for agentic AI delegation. Two paths:

**Option A: Attach to an existing WG**
- RATS WG handles trust chains and attestation — closest fit
- OAuth WG handles token delegation — relevant for the authorization layer
- Requires a WG chair to adopt the draft; takes longer

**Option B: Propose a new WG via BoF**
- File a Birds of a Feather (BoF) session request at an upcoming IETF meeting
- IETF 123 (San Francisco, July 2025) or IETF 124 (Dublin, November 2025) are nearest opportunities
- BoF requires a problem statement, charter draft, and ~5 people willing to contribute
- If the BoF is approved and the WG chartered, HDP and IPP would both be in scope

**Recommended near-term action:** File the individual draft now. Attach to RATS WG mailing list. Assess BoF interest at IETF 123.

---

## Engagement Beyond IETF

### OpenID Foundation

Engage for feedback on the principal identity model and OAuth/OIDC integration patterns. HDP's `id_type: 'opaque' | 'email' | 'did'` maps naturally to OIDC subject identifiers. The OpenID Foundation's [Digital Credentials](https://openid.net/wg/digital-credentials/) and [FAPI](https://openid.net/wg/fapi/) working groups are relevant.

### AI Safety and Governance Venues

HDP's provenance model is directly relevant to AI accountability frameworks. Engage:
- **NIST AI RMF** — HDP maps to the "Govern" and "Map" functions
- **EU AI Act** — HDP's audit trail supports transparency and human oversight requirements
- **Partnership on AI** — technical community engagement

### Academic

Submit to:
- IEEE S&P, CCS, USENIX Security (security track)
- ACM FAccT (fairness, accountability, transparency)
- Workshop on Trustworthy AI at major ML conferences

---

## Immediate Actions

| Priority | Action | Owner | Timeline |
|---|---|---|---|
| 🔴 High | Draft `draft-helixar-hdp-agentic-delegation-00` | Helixar | Before IETF 123 |
| 🔴 High | Subscribe to `rats@ietf.org` and `oauth@ietf.org` | Helixar | This week |
| 🟡 Medium | Post announcement to IETF mailing lists | Helixar | On draft submission |
| 🟡 Medium | Engage OpenID Foundation Digital Credentials WG | Helixar | Q2 2026 |
| 🟢 Low | Assess BoF viability for IETF 123 | Helixar | April 2026 |
| 🟢 Low | Submit to academic workshop | Helixar | Per CFP deadlines |

---

## Resources

- [IETF Author Tools](https://author.ietf.org/) — draft authoring and XML/RFC conversion
- [Datatracker](https://datatracker.ietf.org/) — draft submission and tracking
- [RATS WG](https://datatracker.ietf.org/wg/rats/about/) — Remote ATtestation procedureS
- [OAuth WG](https://datatracker.ietf.org/wg/oauth/about/) — OAuth and token standards
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) — OAuth 2.0 Token Exchange (related work)
- [IPP draft-haberkamp-ipp-00](https://datatracker.ietf.org/doc/html/draft-haberkamp-ipp-00) — the protocol to position against
- [HDP COMPARISON.md](../../COMPARISON.md) — technical comparison (source material for Section 9.1)
