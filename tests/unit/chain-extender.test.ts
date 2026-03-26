import { describe, it, expect } from 'vitest'
import { extendChain } from '../../src/chain/extender.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { signRoot } from '../../src/crypto/sign.js'
import type { HdpToken } from '../../src/types/token.js'

async function makeBaseToken(): Promise<{ token: HdpToken; privateKey: Uint8Array; publicKey: Uint8Array }> {
  const { privateKey, publicKey } = await generateKeyPair()
  const unsigned = {
    hdp: '0.1' as const,
    header: { token_id: 'test-token-id', issued_at: Date.now(), expires_at: Date.now() + 3600000, session_id: 'sess-1', version: '0.1' },
    principal: { id: 'u', id_type: 'opaque' as const },
    scope: { intent: 'test', data_classification: 'public' as const, network_egress: false, persistence: false, max_hops: 3 },
    chain: [] as any[],
  }
  const signature = await signRoot(unsigned as any, privateKey, 'k1')
  const token: HdpToken = { ...unsigned, signature }
  return { token, privateKey, publicKey }
}

describe('extendChain', () => {
  it('appends a hop record with correct seq', async () => {
    const { token, privateKey } = await makeBaseToken()
    const extended = await extendChain(token, {
      agent_id: 'orch-001', agent_type: 'orchestrator', action_summary: 'plan task', parent_hop: 0,
    }, privateKey)
    expect(extended.chain).toHaveLength(1)
    expect(extended.chain[0].seq).toBe(1)
    expect(extended.chain[0].agent_id).toBe('orch-001')
    expect(typeof extended.chain[0].hop_signature).toBe('string')
    expect(extended.chain[0].hop_signature.length).toBeGreaterThan(0)
  })

  it('increments seq for subsequent hops', async () => {
    const { token, privateKey } = await makeBaseToken()
    const hop1 = await extendChain(token, { agent_id: 'a1', agent_type: 'orchestrator', action_summary: 's1', parent_hop: 0 }, privateKey)
    const hop2 = await extendChain(hop1, { agent_id: 'a2', agent_type: 'sub-agent', action_summary: 's2', parent_hop: 1 }, privateKey)
    expect(hop2.chain[1].seq).toBe(2)
  })

  it('throws when max_hops would be exceeded', async () => {
    const { token, privateKey } = await makeBaseToken()
    let t = token
    t = await extendChain(t, { agent_id: 'a1', agent_type: 'orchestrator', action_summary: 'x', parent_hop: 0 }, privateKey)
    t = await extendChain(t, { agent_id: 'a2', agent_type: 'sub-agent', action_summary: 'x', parent_hop: 1 }, privateKey)
    t = await extendChain(t, { agent_id: 'a3', agent_type: 'sub-agent', action_summary: 'x', parent_hop: 2 }, privateKey)
    await expect(extendChain(t, { agent_id: 'a4', agent_type: 'sub-agent', action_summary: 'x', parent_hop: 3 }, privateKey))
      .rejects.toThrow('MAX_HOPS_EXCEEDED')
  })

  it('does not mutate the original token', async () => {
    const { token, privateKey } = await makeBaseToken()
    const originalChainLength = token.chain.length
    await extendChain(token, { agent_id: 'a1', agent_type: 'orchestrator', action_summary: 'x', parent_hop: 0 }, privateKey)
    expect(token.chain).toHaveLength(originalChainLength)
  })
})
