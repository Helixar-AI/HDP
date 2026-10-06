import { describe, it, expect, vi } from 'vitest'
import { verifyPrincipalChain } from '../../src/token/multi-principal.js'
import { issueSupersedingToken } from '../../src/token/reauth.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('verifyPrincipalChain joint-approval audit', () => {
  it('audits a single-token chain without inferring a relationship', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-mp-01',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'single auth', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
    })

    const result = await verifyPrincipalChain([{ token, publicKey }])
    expect(result.valid).toBe(true)
    expect(result.relationship).toBe('unknown')
    expect(result.results).toEqual([{ valid: true }])
  })

  it('reports joint approval only when trusted relationship context is supplied', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const t1 = await issueToken({
      sessionId: 'sess-mp-02',
      principal: { id: 'alice', id_type: 'opaque', display_name: 'Alice' },
      scope: { intent: 'high-risk action requires two approvals', data_classification: 'confidential', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })
    const t2 = await issueSupersedingToken({
      original: t1,
      principal: { id: 'bob', id_type: 'opaque', display_name: 'Bob' },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    const unclassified = await verifyPrincipalChain([
      { token: t1, publicKey: alice.publicKey },
      { token: t2, publicKey: bob.publicKey },
    ])
    const classified = await verifyPrincipalChain([
      { token: t1, publicKey: alice.publicKey },
      { token: t2, publicKey: bob.publicKey },
    ], { relationshipContext: { type: 'joint_approval', authenticated: true } })

    expect(unclassified.valid).toBe(true)
    expect(unclassified.relationship).toBe('unknown')
    expect(classified.valid).toBe(true)
    expect(classified.relationship).toBe('joint_approval')
    expect(classified.results).toEqual([{ valid: true }, { valid: true }])
    expect(t2.header.parent_token_id).toBe(t1.header.token_id)
  })

  it('reports a broken parent_token_id link', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const t1 = await issueToken({
      sessionId: 'sess-mp-03',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })
    const t2 = await issueToken({
      sessionId: 'sess-mp-03',
      principal: { id: 'bob', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    const result = await verifyPrincipalChain([
      { token: t1, publicKey: alice.publicKey },
      { token: t2, publicKey: bob.publicKey },
    ])
    expect(result.valid).toBe(false)
    expect(result.failedAt).toBe(1)
    expect(result.error?.code).toBe('CHAIN_INTEGRITY')
  })

  it('reports a token with an invalid signature', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const t1 = await issueToken({
      sessionId: 'sess-mp-04',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })
    const t2 = await issueSupersedingToken({
      original: t1,
      principal: { id: 'bob', id_type: 'opaque' },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    const result = await verifyPrincipalChain([
      { token: t1, publicKey: alice.publicKey },
      { token: t2, publicKey: alice.publicKey },
    ])
    expect(result.valid).toBe(false)
    expect(result.failedAt).toBe(1)
    expect(result.results[1]).toMatchObject({ valid: false, failedStep: 2 })
  })

  it('does not use expiry to reject either token in the audit', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const t1 = await issueToken({
      sessionId: 'sess-mp-05',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key', expiresInMs: 1,
    })
    const t2 = await issueSupersedingToken({
      original: t1,
      principal: { id: 'bob', id_type: 'opaque' },
      signingKey: bob.privateKey, keyId: 'bob-key', expiresInMs: 1,
    })

    vi.spyOn(Date, 'now').mockReturnValue(Number.MAX_SAFE_INTEGER)
    const result = await verifyPrincipalChain([
      { token: t1, publicKey: alice.publicKey },
      { token: t2, publicKey: bob.publicKey },
    ])
    vi.restoreAllMocks()
    expect(result.valid).toBe(true)
    expect(result.results).toEqual([{ valid: true }, { valid: true }])
  })

  it('reports a shared-session mismatch without changing token integrity results', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const t1 = await issueToken({
      sessionId: 'sess-mp-06',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })
    const t2 = await issueSupersedingToken({
      original: t1, sessionId: 'different-session',
      principal: { id: 'bob', id_type: 'opaque' },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    const result = await verifyPrincipalChain([
      { token: t1, publicKey: alice.publicKey },
      { token: t2, publicKey: bob.publicKey },
    ])
    expect(result.valid).toBe(false)
    expect(result.failedAt).toBe(1)
    expect(result.error?.code).toBe('SESSION_MISMATCH')
    expect(result.results).toEqual([{ valid: true }, { valid: true }])
  })

  it('returns an audit failure for an empty chain', async () => {
    const result = await verifyPrincipalChain([])
    expect(result.valid).toBe(false)
    expect(result.results).toHaveLength(0)
  })
})
