import { describe, it, expect } from 'vitest'
import { generateKeyPair, exportPublicKey } from '../../src/crypto/keys.js'
import { signRoot, signHop } from '../../src/crypto/sign.js'
import { verifyRoot, verifyHop } from '../../src/crypto/verify.js'

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

describe('verifyRoot', () => {
  it('returns true for a valid root signature', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = { header: { token_id: 't1' }, principal: { id: 'u' }, scope: { intent: 'x' } }
    const sig = await signRoot(token as any, privateKey, 'k1')
    const result = await verifyRoot(token as any, sig, publicKey)
    expect(result).toBe(true)
  })

  it('returns false if scope is tampered after signing', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = { header: { token_id: 't1' }, principal: { id: 'u' }, scope: { intent: 'x' } }
    const sig = await signRoot(token as any, privateKey, 'k1')
    const tampered = { ...token, scope: { intent: 'EVIL' } }
    const result = await verifyRoot(tampered as any, sig, publicKey)
    expect(result).toBe(false)
  })
})

describe('verifyHop', () => {
  it('returns true for a valid hop signature', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const hop = { seq: 1, agent_id: 'a1', agent_type: 'orchestrator' as const, timestamp: 1000, action_summary: 't', parent_hop: 0 }
    const rootSig = 'rootsig-value'
    const hopSig = await signHop([hop as any], rootSig, privateKey)
    const result = await verifyHop([hop as any], rootSig, hopSig, publicKey)
    expect(result).toBe(true)
  })

  it('returns false if a prior hop record is tampered', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const hop1 = { seq: 1, agent_id: 'a1', agent_type: 'orchestrator' as const, timestamp: 1000, action_summary: 'original', parent_hop: 0 }
    const hop2 = { seq: 2, agent_id: 'a2', agent_type: 'sub-agent' as const, timestamp: 2000, action_summary: 't', parent_hop: 1 }
    const rootSig = 'r'
    const hop2Sig = await signHop([hop1 as any, hop2 as any], rootSig, privateKey)
    const tampered1 = { ...hop1, action_summary: 'EVIL' }
    const result = await verifyHop([tampered1 as any, hop2 as any], rootSig, hop2Sig, publicKey)
    expect(result).toBe(false)
  })
})
