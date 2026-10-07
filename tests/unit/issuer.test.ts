import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { verifyToken } from '../../src/token/verifier.js'

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

  it('issues a verifiable token with a valid custom id_type', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 's-custom',
      principal: { id: 'u', id_type: 'x-custom' },
      scope: { intent: 'x', data_classification: 'internal', network_egress: false, persistence: false },
      signingKey: privateKey,
      keyId: 'k-custom',
    })

    expect(token.principal.id_type).toBe('x-custom')
    expect(await verifyToken(token, { publicKey })).toEqual({ valid: true })
  })

  it('rejects a custom id_type ending in a newline before returning a token', async () => {
    const { privateKey } = await generateKeyPair()

    await expect(issueToken({
      sessionId: 's-invalid-custom',
      principal: { id: 'u', id_type: 'x-custom\n' },
      scope: { intent: 'x', data_classification: 'internal', network_egress: false, persistence: false },
      signingKey: privateKey,
      keyId: 'k-custom',
    })).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })
})
