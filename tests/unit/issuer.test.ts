import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('issueToken', () => {
  it('returns a fully signed HDP token', async () => {
    const { privateKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-test-1',
      principal: { id: 'usr_001', id_type: 'opaque' },
      scope: { intent: 'fetch weather data', data_classification: 'public', network_egress: true, persistence: false },
      signingKey: privateKey,
      keyId: 'key-2026-01',
    })
    expect(token.hdp).toBe('0.1')
    expect(token.signature.alg).toBe('Ed25519')
    expect(token.signature.kid).toBe('key-2026-01')
    expect(token.signature.value.length).toBeGreaterThan(0)
  })

  it('issued token passes schema validation', async () => {
    const { validateToken } = await import('../../src/schema/validator.js')
    const { privateKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 's1',
      principal: { id: 'u', id_type: 'uuid' },
      scope: { intent: 'x', data_classification: 'internal', network_egress: false, persistence: false },
      signingKey: privateKey,
      keyId: 'k1',
    })
    expect(() => validateToken(token)).not.toThrow()
  })
})
