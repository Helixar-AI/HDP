// tests/security/chain-tampering.test.ts
import { describe, it, expect } from 'vitest'
import { verifyToken } from '../../src/token/verifier.js'
import { issueToken } from '../../src/token/issuer.js'
import { extendChain } from '../../src/chain/extender.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

async function twoHopToken() {
  const { privateKey, publicKey } = await generateKeyPair()
  let token = await issueToken({
    sessionId: 'sess-1',
    principal: { id: 'u', id_type: 'opaque' },
    scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
    signingKey: privateKey, keyId: 'k1',
  })
  token = await extendChain(token, { agent_id: 'orch', agent_type: 'orchestrator', action_summary: 'orchestrate', parent_hop: 0 }, privateKey)
  token = await extendChain(token, { agent_id: 'sub', agent_type: 'sub-agent', action_summary: 'execute', parent_hop: 1 }, privateKey)
  return { token, publicKey }
}

describe('12.3 Delegation Chain Poisoning', () => {
  it('detects modification of a prior hop action_summary', async () => {
    const { token, publicKey } = await twoHopToken()
    const poisoned = {
      ...token,
      chain: [
        { ...token.chain[0], action_summary: 'EVIL ACTION' },
        token.chain[1],
      ],
    }
    const result = await verifyToken(poisoned, { publicKey, currentSessionId: 'sess-1' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('SIGNATURE_INVALID')
  })

  it('detects a removed hop (seq gap)', async () => {
    const { token, publicKey } = await twoHopToken()
    // Remove hop 1, leaving only hop 2 — creates seq gap
    const gapped = { ...token, chain: [token.chain[1]] }
    const result = await verifyToken(gapped, { publicKey, currentSessionId: 'sess-1' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('CHAIN_INTEGRITY')
  })
})
