// tests/security/replay-attack.test.ts
import { afterEach, describe, it, expect, vi } from 'vitest'
import { auditToken, verifyToken } from '../../src/token/verifier.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('record-only session and expiry auditing', () => {
  it('verifies a record from another session and reports the mismatch', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'session-original',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
    })
    const result = await verifyToken(token, { publicKey })
    const report = await auditToken(token, { publicKey, sessionId: 'session-DIFFERENT' })
    expect(result).toEqual({ valid: true })
    expect(report.session).toEqual({ status: 'mismatch' })
  })

  it('verifies an expired record without waiting for its expiry', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(1_000)
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-1',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
      expiresInMs: 1,
    })
    vi.setSystemTime(10_000)
    const result = await verifyToken(token, { publicKey })
    const report = await auditToken(token, { publicKey })
    expect(result).toEqual({ valid: true })
    expect(report.recordingPeriod).toEqual({ status: 'within_period' })
  })
})
