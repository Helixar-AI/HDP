// tests/integration/full-chain.test.ts
import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { extendChain } from '../../src/chain/extender.js'
import { verifyToken } from '../../src/token/verifier.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('Full Delegation Chain: Principal → Orchestrator → Sub-agent → Tool', () => {
  it('verifies a valid 3-hop chain end-to-end', async () => {
    const { privateKey, publicKey } = await generateKeyPair()

    // Issue token (Principal authorization event)
    let token = await issueToken({
      sessionId: 'sess-integration-001',
      principal: { id: 'usr_analyst_opaque', id_type: 'opaque', display_name: 'Security Analyst' },
      scope: {
        intent: 'Scan internal API surface for exposed version strings.',
        authorized_tools: ['http_get'],
        authorized_resources: ['https://api.internal.example.com/*'],
        data_classification: 'confidential',
        network_egress: true,
        persistence: false,
        max_hops: 3,
        constraints: [{ type: 'action_count', params: { tool: 'http_get', max_count: 50 } }],
      },
      signingKey: privateKey,
      keyId: 'helixar-test-key-2026',
    })

    // Hop 1: Principal → Orchestrator
    token = await extendChain(token, {
      agent_id: 'orch-helixar-v031',
      agent_type: 'orchestrator',
      agent_fingerprint: 'sha256:mock-fingerprint-orch',
      action_summary: 'Decompose scan task and delegate to sub-agents.',
      parent_hop: 0,
    }, privateKey)

    // Hop 2: Orchestrator → Sub-agent
    token = await extendChain(token, {
      agent_id: 'subagent-http-scanner-v12',
      agent_type: 'sub-agent',
      agent_fingerprint: 'sha256:mock-fingerprint-sub',
      action_summary: 'Execute HTTP GET requests against authorized resource list.',
      parent_hop: 1,
    }, privateKey)

    // Hop 3: Sub-agent → Tool Executor
    token = await extendChain(token, {
      agent_id: 'tool-exec-http-001',
      agent_type: 'tool-executor',
      action_summary: 'Invoke http_get against https://api.internal.example.com/version.',
      parent_hop: 2,
    }, privateKey)

    expect(token.chain).toHaveLength(3)

    // Verify the full chain
    const result = await verifyToken(token, {
      publicKey,
      currentSessionId: 'sess-integration-001',
    })

    expect(result.valid).toBe(true)
    expect(result.error).toBeUndefined()
  })

  it('fails verification when the chain would exceed max_hops', async () => {
    const { privateKey } = await generateKeyPair()
    let token = await issueToken({
      sessionId: 's1',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', data_classification: 'public', network_egress: false, persistence: false, max_hops: 3 },
      signingKey: privateKey, keyId: 'k1',
    })
    token = await extendChain(token, { agent_id: 'a1', agent_type: 'orchestrator', action_summary: 'h1', parent_hop: 0 }, privateKey)
    token = await extendChain(token, { agent_id: 'a2', agent_type: 'sub-agent', action_summary: 'h2', parent_hop: 1 }, privateKey)
    token = await extendChain(token, { agent_id: 'a3', agent_type: 'tool-executor', action_summary: 'h3', parent_hop: 2 }, privateKey)
    await expect(
      extendChain(token, { agent_id: 'a4', agent_type: 'sub-agent', action_summary: 'h4', parent_hop: 3 }, privateKey)
    ).rejects.toThrow('MAX_HOPS_EXCEEDED')
  })
})
