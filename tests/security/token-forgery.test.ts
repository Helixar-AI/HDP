// tests/security/token-forgery.test.ts
import { describe, it, expect } from 'vitest'
import { verifyToken } from '../../src/token/verifier.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('12.1 Token Injection and Forgery', () => {
  it('rejects a token signed by a different key', async () => {
    const { privateKey: attackerKey } = await generateKeyPair()
    const { publicKey: legitimatePublicKey } = await generateKeyPair()

    const forgedToken = await issueToken({
      sessionId: 'sess-target',
      principal: { id: 'attacker', id_type: 'opaque' },
      scope: { intent: 'malicious task', data_classification: 'restricted', network_egress: true, persistence: true },
      signingKey: attackerKey,
      keyId: 'attacker-key',
    })

    const result = await verifyToken(forgedToken, { publicKey: legitimatePublicKey, currentSessionId: 'sess-target' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('SIGNATURE_INVALID')
  })

  it('rejects a token with tampered scope after signing', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-1',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'safe task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey,
      keyId: 'k1',
    })
    const tampered = { ...token, scope: { ...token.scope, data_classification: 'restricted' as const, authorized_tools: ['*'] } }
    const result = await verifyToken(tampered, { publicKey, currentSessionId: 'sess-1' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('SIGNATURE_INVALID')
  })
})
