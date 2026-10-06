import { describe, it, expect, vi } from 'vitest'
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
    const result = await verifyToken(token, { publicKey })
    expect(result).toEqual({ valid: true })
  })

  it('keeps expiry out of integrity verification', async () => {
    const { token, publicKey } = await makeToken()
    vi.spyOn(Date, 'now').mockReturnValue(Number.MAX_SAFE_INTEGER)
    const result = await verifyToken(token, {
      publicKey,
    })
    vi.restoreAllMocks()
    expect(result).toEqual({ valid: true })
  })

  it('INVALID if root signature tampered', async () => {
    const { token, publicKey } = await makeToken()
    const tampered = { ...token, scope: { ...token.scope, intent: 'EVIL TASK' } }
    const result = await verifyToken(tampered as any, { publicKey })
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.failedStep).toBe(2)
    expect(result.error?.code).toBe('SIGNATURE_INVALID')
  })

  it('reports an unknown hdp version at step 1', async () => {
    const { token, publicKey } = await makeToken()
    const badVersion = { ...token, hdp: '99.0', header: { ...token.header, version: '99.0' } }
    const result = await verifyToken(badVersion, { publicKey })
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.failedStep).toBe(1)
  })
})
