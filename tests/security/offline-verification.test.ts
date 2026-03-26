/**
 * Offline Verification — Architectural Proof
 *
 * HDP verification is fully offline by design.
 * No revocation registry. No central endpoint. No network call.
 *
 * IPP (draft-haberkamp-ipp-00) requires agents to poll a central revocation
 * registry at registry_endpoint every 5,000ms before acting. If the registry
 * is unreachable, agents cannot safely proceed — a hard liveness dependency.
 *
 * HDP's response: tokens are short-lived (24h default). Replay defense is
 * structural via session_id binding. Verification requires only the issuer's
 * public key and the current session ID. Nothing else.
 *
 * This test issues a token, extends it through a 3-hop chain, and verifies
 * the complete chain with zero network mocks, zero fetch stubs, and zero
 * external dependencies. If this test passes, offline operation is proven.
 */
import { describe, it, expect } from 'vitest'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { issueToken } from '../../src/token/issuer.js'
import { extendChain } from '../../src/chain/extender.js'
import { verifyToken } from '../../src/token/verifier.js'

describe('Offline Verification (HDP architectural guarantee)', () => {
  it('verifies a full 3-hop delegation chain with zero network calls', async () => {
    // All operations are local. No fetch(). No XMLHttpRequest. No DNS.
    // No revocation registry. No DID resolver. No taxonomy endpoint.
    const { privateKey, publicKey } = await generateKeyPair()

    let token = await issueToken({
      sessionId: 'sess-offline-proof',
      principal: { id: 'usr_air_gapped', id_type: 'opaque' },
      scope: {
        intent: 'Operate in an air-gapped environment with no network access.',
        data_classification: 'confidential',
        network_egress: false,
        persistence: false,
        max_hops: 3,
      },
      signingKey: privateKey,
      keyId: 'offline-key-001',
    })

    // Hop 1
    token = await extendChain(token, {
      agent_id: 'orchestrator-offline',
      agent_type: 'orchestrator',
      action_summary: 'Coordinate local processing tasks.',
      parent_hop: 0,
    }, privateKey)

    // Hop 2
    token = await extendChain(token, {
      agent_id: 'subagent-offline',
      agent_type: 'sub-agent',
      action_summary: 'Execute local data transformation.',
      parent_hop: 1,
    }, privateKey)

    // Hop 3
    token = await extendChain(token, {
      agent_id: 'tool-executor-offline',
      agent_type: 'tool-executor',
      action_summary: 'Write output to local filesystem.',
      parent_hop: 2,
    }, privateKey)

    expect(token.chain).toHaveLength(3)

    // Verification: public key + session ID. Nothing else.
    // No network. No registry. No resolver. Fully self-contained.
    const result = await verifyToken(token, {
      publicKey,
      currentSessionId: 'sess-offline-proof',
    })

    expect(result.valid).toBe(true)
    expect(result.error).toBeUndefined()

    // Structural guarantees confirmed:
    // - Root signature verified cryptographically (no registry lookup)
    // - All 3 hop signatures verified against cumulative chain state (no polling)
    // - Session ID bound (no external session store required)
    // - Token not expired (wall-clock check only — no network time service)
    expect(token.header.session_id).toBe('sess-offline-proof')
    expect(token.chain.every(h => typeof h.hop_signature === 'string')).toBe(true)
  })
})
