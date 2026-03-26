import { describe, it, expect } from 'vitest'
import { verifyToken } from '../../src/token/verifier.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

async function makeToken(overrides?: Record<string, unknown>) {
  const { privateKey, publicKey } = await generateKeyPair()
  const token = await issueToken({
    sessionId: 'sess-abc',
    principal: { id: 'usr_test', id_type: 'opaque' },
    scope: { intent: 'test task', data_classification: 'public', network_egress: false, persistence: false },
    signingKey: privateKey,
    keyId: 'test-key',
  })
  return { token: { ...token, ...overrides }, publicKey, privateKey }
}

describe('verifyToken', () => {
  it('VALID for a freshly issued token', async () => {
    const { token, publicKey } = await makeToken()
    const result = await verifyToken(token, { publicKey, currentSessionId: 'sess-abc' })
    expect(result.valid).toBe(true)
  })

  it('INVALID for an expired token', async () => {
    const { token, publicKey } = await makeToken()
    const expired = { ...token, header: { ...token.header, expires_at: Date.now() - 1000 } }
    const result = await verifyToken(expired as any, { publicKey, currentSessionId: 'sess-abc' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('TOKEN_EXPIRED')
  })

  it('INVALID if root signature tampered', async () => {
    const { token, publicKey } = await makeToken()
    const tampered = { ...token, scope: { ...token.scope, intent: 'EVIL TASK' } }
    const result = await verifyToken(tampered as any, { publicKey, currentSessionId: 'sess-abc' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('SIGNATURE_INVALID')
  })

  it('INVALID if session_id does not match current session', async () => {
    const { token, publicKey } = await makeToken()
    const result = await verifyToken(token, { publicKey, currentSessionId: 'DIFFERENT-SESSION' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('SESSION_MISMATCH')
  })

  it('INVALID if unknown hdp version', async () => {
    const { token, publicKey } = await makeToken()
    const badVersion = { ...token, hdp: '99.0' as any }
    const result = await verifyToken(badVersion, { publicKey, currentSessionId: 'sess-abc' })
    expect(result.valid).toBe(false)
  })
})
