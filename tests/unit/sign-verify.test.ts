import { describe, it, expect } from 'vitest'
import * as ed from '@noble/ed25519'
import { canonicalize } from 'json-canonicalize'
import { generateKeyPair, exportPublicKey } from '../../src/crypto/keys.js'
import { signRoot, signHop } from '../../src/crypto/sign.js'
import { verifyRoot, verifyHop } from '../../src/crypto/verify.js'
import type { UnsignedToken } from '../../src/types/token.js'

function unsignedToken(): UnsignedToken {
  return {
    hdp: '0.1',
    header: {
      token_id: '550e8400-e29b-41d4-a716-446655440000',
      issued_at: 1000,
      expires_at: 2000,
      session_id: 's1',
      version: '0.1',
    },
    principal: { id: 'u', id_type: 'opaque' },
    scope: {
      intent: 'x',
      data_classification: 'public',
      network_egress: false,
      persistence: false,
    },
    chain: [],
  }
}

describe('signRoot', () => {
  it('returns a base64url string signature', async () => {
    const { privateKey } = await generateKeyPair()
    const sig = await signRoot(unsignedToken(), privateKey, 'key-1')
    expect(sig.alg).toBe('Ed25519')
    expect(sig.kid).toBe('key-1')
    expect(sig.value).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(sig).toEqual(expect.objectContaining({ alg: 'Ed25519', kid: 'key-1' }))
    expect(sig).not.toHaveProperty('signed_fields')
  })

  it('signs the canonical unsigned issuance token including hdp and empty chain', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const unsigned = unsignedToken()
    const sig = await signRoot(unsigned, privateKey, 'key-1')
    const message = new TextEncoder().encode(canonicalize(unsigned))
    expect(await ed.verifyAsync(Buffer.from(sig.value, 'base64url'), message, publicKey)).toBe(true)
  })

  it('rejects schema-invalid input before signing', async () => {
    const { privateKey } = await generateKeyPair()
    const invalid = unsignedToken()
    invalid.header.expires_at = invalid.header.issued_at
    await expect(signRoot(invalid, privateKey, 'key-1')).rejects.toThrow('expires_at')
  })
})

describe('signHop', () => {
  it('returns a base64url signature string', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const hop = { seq: 1, agent_id: 'a1', agent_type: 'orchestrator', timestamp: 1000, action_summary: 'test', parent_hop: 0 }
    const rootSig = 'abc123'
    const sig = await signHop([hop as any], rootSig, privateKey)
    expect(typeof sig).toBe('string')
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/)
    const message = new TextEncoder().encode(canonicalize([rootSig, hop]))
    expect(await ed.verifyAsync(Buffer.from(sig, 'base64url'), message, publicKey)).toBe(true)
  })
})

describe('verifyRoot', () => {
  it('returns true for a valid root signature', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = unsignedToken()
    const sig = await signRoot(token, privateKey, 'k1')
    const result = await verifyRoot(token as any, sig, publicKey)
    expect(result).toBe(true)
  })

  it('returns false if scope is tampered after signing', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = unsignedToken()
    const sig = await signRoot(token, privateKey, 'k1')
    const tampered = { ...token, scope: { intent: 'EVIL' } }
    const result = await verifyRoot(tampered as any, sig, publicKey)
    expect(result).toBe(false)
  })

  it('returns false if the protocol version is tampered after signing', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = unsignedToken()
    const sig = await signRoot(token, privateKey, 'k1')
    expect(await verifyRoot({ ...token, hdp: '0.2' } as any, sig, publicKey)).toBe(false)
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
