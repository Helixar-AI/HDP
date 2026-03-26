import { describe, it, expect } from 'vitest'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { signRoot, signHop } from '../../src/crypto/sign.js'

describe('signRoot', () => {
  it('returns a base64url string signature', async () => {
    const { privateKey } = await generateKeyPair()
    const payload = { header: { token_id: 't1' }, principal: { id: 'u' }, scope: { intent: 'x' } }
    const sig = await signRoot(payload as any, privateKey, 'key-1')
    expect(sig.alg).toBe('Ed25519')
    expect(sig.kid).toBe('key-1')
    expect(sig.value).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(sig.signed_fields).toEqual(['header', 'principal', 'scope'])
  })
})

describe('signHop', () => {
  it('returns a base64url signature string', async () => {
    const { privateKey } = await generateKeyPair()
    const hop = { seq: 1, agent_id: 'a1', agent_type: 'orchestrator', timestamp: 1000, action_summary: 'test', parent_hop: 0 }
    const rootSig = 'abc123'
    const sig = await signHop([hop as any], rootSig, privateKey)
    expect(typeof sig).toBe('string')
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})
