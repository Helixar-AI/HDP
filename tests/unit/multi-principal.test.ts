import { describe, it, expect } from 'vitest'
import { verifyPrincipalChain } from '../../src/token/multi-principal.js'
import { issueReAuthToken } from '../../src/token/reauth.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('verifyPrincipalChain', () => {
  it('verifies a single-token chain', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-mp-01',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'single auth', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
    })

    const result = await verifyPrincipalChain(
      [{ token, publicKey }],
      { currentSessionId: 'sess-mp-01' }
    )
    expect(result.valid).toBe(true)
    expect(result.results).toHaveLength(1)
  })

  it('verifies a two-principal joint authorization chain', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()

    // Alice issues T1
    const t1 = await issueToken({
      sessionId: 'sess-mp-02',
      principal: { id: 'alice', id_type: 'opaque', display_name: 'Alice' },
      scope: { intent: 'high-risk action — joint approval required', data_classification: 'confidential', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })

    // Bob issues T2 pointing to T1
    const t2 = await issueReAuthToken({
      original: t1,
      principal: { id: 'bob', id_type: 'opaque', display_name: 'Bob' },
      scope: { intent: 'high-risk action — joint approval required', data_classification: 'confidential', network_egress: false, persistence: false },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    const result = await verifyPrincipalChain(
      [
        { token: t1, publicKey: alice.publicKey },
        { token: t2, publicKey: bob.publicKey },
      ],
      { currentSessionId: 'sess-mp-02' }
    )

    expect(result.valid).toBe(true)
    expect(result.results).toHaveLength(2)
    expect(t2.header.parent_token_id).toBe(t1.header.token_id)
  })

  it('fails if parent_token_id link is broken', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()

    const t1 = await issueToken({
      sessionId: 'sess-mp-03',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })

    // T2 does NOT have parent_token_id pointing to T1 (it's a fresh token)
    const t2 = await issueToken({
      sessionId: 'sess-mp-03',
      principal: { id: 'bob', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    const result = await verifyPrincipalChain(
      [
        { token: t1, publicKey: alice.publicKey },
        { token: t2, publicKey: bob.publicKey },
      ],
      { currentSessionId: 'sess-mp-03' }
    )

    expect(result.valid).toBe(false)
    expect(result.failedAt).toBe(1)
    expect(result.error?.message).toContain('CHAIN_INTEGRITY')
  })

  it('fails if one token has an invalid signature', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()

    const t1 = await issueToken({
      sessionId: 'sess-mp-04',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
    })

    const t2 = await issueReAuthToken({
      original: t1,
      principal: { id: 'bob', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    // Pass alice's key for t2 (wrong key — should fail signature check)
    const result = await verifyPrincipalChain(
      [
        { token: t1, publicKey: alice.publicKey },
        { token: t2, publicKey: alice.publicKey }, // wrong key
      ],
      { currentSessionId: 'sess-mp-04' }
    )

    expect(result.valid).toBe(false)
    expect(result.failedAt).toBe(1)
  })

  it('fails if a token in the chain is expired', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()

    // T1: Alice issues with a very short lifetime (already expired)
    const t1 = await issueToken({
      sessionId: 'sess-mp-05',
      principal: { id: 'alice', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: alice.privateKey, keyId: 'alice-key',
      expiresInMs: 1, // expires immediately
    })

    // T2: Bob re-authorizes, long lifetime
    const t2 = await issueReAuthToken({
      original: t1,
      principal: { id: 'bob', id_type: 'opaque' },
      scope: { intent: 'task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: bob.privateKey, keyId: 'bob-key',
    })

    // Verify with `now` advanced past T1's expiry
    const futureNow = Date.now() + 60_000
    const result = await verifyPrincipalChain(
      [
        { token: t1, publicKey: alice.publicKey },
        { token: t2, publicKey: bob.publicKey },
      ],
      { currentSessionId: 'sess-mp-05', now: futureNow }
    )

    expect(result.valid).toBe(false)
    expect(result.failedAt).toBe(0) // T1 fails first
    expect(result.error?.code).toBe('TOKEN_EXPIRED')
  })

  it('returns empty result for empty chain', async () => {
    const result = await verifyPrincipalChain([], { currentSessionId: 'sess' })
    expect(result.valid).toBe(false)
    expect(result.results).toHaveLength(0)
  })
})
