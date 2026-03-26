import { describe, it, expect } from 'vitest'
import { issueReAuthToken } from '../../src/token/reauth.js'
import { issueToken } from '../../src/token/issuer.js'
import { extendChain } from '../../src/chain/extender.js'
import { verifyToken } from '../../src/token/verifier.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { HdpMaxHopsExceededError } from '../../src/types/errors.js'

describe('issueReAuthToken', () => {
  it('creates a new token with parent_token_id pointing to the original', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-001',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'initial task', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey,
      keyId: 'k1',
    })

    const reAuth = await issueReAuthToken({ original, signingKey: privateKey, keyId: 'k1' })

    expect(reAuth.header.parent_token_id).toBe(original.header.token_id)
    expect(reAuth.header.token_id).not.toBe(original.header.token_id)
    expect(reAuth.chain).toHaveLength(0)
  })

  it('inherits scope and session from original by default', async () => {
    const { privateKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-002',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'original intent', data_classification: 'internal', network_egress: true, persistence: false },
      signingKey: privateKey,
      keyId: 'k1',
    })

    const reAuth = await issueReAuthToken({ original, signingKey: privateKey, keyId: 'k1' })

    expect(reAuth.header.session_id).toBe('sess-002')
    expect(reAuth.scope.intent).toBe('original intent')
    expect(reAuth.scope.data_classification).toBe('internal')
  })

  it('allows scope expansion on re-authorization', async () => {
    const { privateKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-003',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'read data', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey,
      keyId: 'k1',
    })

    const reAuth = await issueReAuthToken({
      original,
      scope: { intent: 'read and write data', max_hops: 3, persistence: true },
      signingKey: privateKey,
      keyId: 'k1',
    })

    expect(reAuth.scope.intent).toBe('read and write data')
    expect(reAuth.scope.max_hops).toBe(3)
    expect(reAuth.scope.persistence).toBe(true)
  })

  it('re-auth token verifies successfully', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-004',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey,
      keyId: 'k1',
    })

    const reAuth = await issueReAuthToken({ original, signingKey: privateKey, keyId: 'k1' })
    const result = await verifyToken(reAuth, { publicKey, currentSessionId: 'sess-004' })

    expect(result.valid).toBe(true)
  })

  it('full streaming session: exhaust max_hops, re-auth, continue chain', async () => {
    const { privateKey, publicKey } = await generateKeyPair()

    // Phase 1: initial token with max_hops: 1
    let token = await issueToken({
      sessionId: 'sess-streaming',
      principal: { id: 'usr_alice', id_type: 'opaque' },
      scope: { intent: 'analyze dataset', data_classification: 'confidential', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey,
      keyId: 'k1',
    })
    token = await extendChain(token, { agent_id: 'orchestrator', agent_type: 'orchestrator', action_summary: 'start analysis', parent_hop: 0 }, privateKey)

    // max_hops exhausted — next extension would throw
    await expect(
      extendChain(token, { agent_id: 'subagent', agent_type: 'sub-agent', action_summary: 'continue', parent_hop: 1 }, privateKey)
    ).rejects.toThrow('MAX_HOPS_EXCEEDED')

    // Phase 2: re-authorize with expanded scope
    const reAuth = await issueReAuthToken({
      original: token,
      scope: { intent: 'analyze dataset — phase 2', data_classification: 'confidential', network_egress: false, persistence: false, max_hops: 2 },
      signingKey: privateKey,
      keyId: 'k1',
    })

    expect(reAuth.header.parent_token_id).toBe(token.header.token_id)

    // Phase 2 chain continues from hop 0
    const extended = await extendChain(reAuth, { agent_id: 'subagent', agent_type: 'sub-agent', action_summary: 'phase 2 analysis', parent_hop: 0 }, privateKey)
    const result = await verifyToken(extended, { publicKey, currentSessionId: 'sess-streaming' })
    expect(result.valid).toBe(true)
  })
})
