// tests/security/replay-attack.test.ts
import { describe, it, expect } from 'vitest'
import { verifyToken } from '../../src/token/verifier.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('12.7 Token Reuse and Replay Attacks', () => {
  it('rejects a valid token used in a different session', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'session-original',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
    })
    const result = await verifyToken(token, { publicKey, currentSessionId: 'session-DIFFERENT' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('SESSION_MISMATCH')
  })

  it('rejects an expired token even with valid signature', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-1',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
      expiresInMs: 1, // expires in 1ms
    })
    await new Promise(r => setTimeout(r, 10)) // let it expire
    const result = await verifyToken(token, { publicKey, currentSessionId: 'sess-1' })
    expect(result.valid).toBe(false)
    expect(result.error?.code).toBe('TOKEN_EXPIRED')
  })
})
