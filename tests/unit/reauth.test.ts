import { afterEach, describe, expect, it, vi } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { issueReAuthToken, issueSupersedingToken } from '../../src/token/reauth.js'
import { extendChain } from '../../src/chain/extender.js'
import { verifyToken } from '../../src/token/verifier.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { HdpMaxHopsExceededError } from '../../src/types/errors.js'

afterEach(() => vi.useRealTimers())

describe('issueSupersedingToken', () => {
  it('signs a new record linked to the original and keeps both records valid', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(1_000)
    const { privateKey, publicKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-001',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'initial task', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey,
      keyId: 'k1',
      expiresInMs: 20_000,
    })
    vi.setSystemTime(6_000)

    const superseding = await issueSupersedingToken({
      original, signingKey: privateKey, keyId: 'k1', expiresInMs: 500,
    })
    const originalVerification = await verifyToken(original, { publicKey })
    const supersedingVerification = await verifyToken(superseding, { publicKey })

    expect(superseding.header.parent_token_id).toBe(original.header.token_id)
    expect(superseding.header.token_id).not.toBe(original.header.token_id)
    expect(superseding.header.issued_at).toBe(6_000)
    expect(superseding.header.expires_at).toBe(6_500)
    expect(superseding.chain).toEqual([])
    expect(originalVerification).toEqual({ valid: true })
    expect(supersedingVerification).toEqual({ valid: true })
  })

  it('inherits principal, scope, and session unless overridden', async () => {
    const { privateKey } = await generateKeyPair()
    const principal = { id: 'u', id_type: 'opaque' as const, display_name: 'User' }
    const scope = { intent: 'original intent', data_classification: 'internal' as const, network_egress: true, persistence: false }
    const original = await issueToken({
      sessionId: 'sess-002', principal, scope, signingKey: privateKey, keyId: 'k1',
    })

    const inherited = await issueSupersedingToken({ original, signingKey: privateKey, keyId: 'k1' })
    const overridden = await issueSupersedingToken({
      original,
      sessionId: 'sess-rotated',
      principal: { id: 'other', id_type: 'opaque' },
      scope: { intent: 'updated intent', persistence: true },
      signingKey: privateKey,
      keyId: 'k1',
    })

    expect(inherited.header.session_id).toBe('sess-002')
    expect(inherited.principal).toEqual(principal)
    expect(inherited.scope).toEqual(scope)
    expect(overridden.header.session_id).toBe('sess-rotated')
    expect(overridden.principal.id).toBe('other')
    expect(overridden.scope.intent).toBe('updated intent')
    expect(overridden.scope.persistence).toBe(true)
  })

  it('rejects a schema-invalid principal before signing a superseding record', async () => {
    const { privateKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-invalid-custom',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'initial task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey,
      keyId: 'k1',
    })

    await expect(issueSupersedingToken({
      original,
      principal: { id: 'u', id_type: 'x-custom\n' },
      signingKey: privateKey,
      keyId: 'k1',
    })).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })

  it('keeps the legacy issueReAuthToken export as an alias', () => {
    expect(issueReAuthToken).toBe(issueSupersedingToken)
  })

  it('declines to extend a full record while a superseding record starts empty', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    let token = await issueToken({
      sessionId: 'sess-streaming',
      principal: { id: 'usr_alice', id_type: 'opaque' },
      scope: { intent: 'analyze dataset', data_classification: 'confidential', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey,
      keyId: 'k1',
    })
    token = await extendChain(token, {
      agent_id: 'orchestrator', agent_type: 'orchestrator', action_summary: 'start analysis', parent_hop: 0,
    }, privateKey)

    await expect(extendChain(token, {
      agent_id: 'subagent', agent_type: 'sub-agent', action_summary: 'continue', parent_hop: 1,
    }, privateKey)).rejects.toBeInstanceOf(HdpMaxHopsExceededError)

    const superseding = await issueSupersedingToken({
      original: token,
      scope: { intent: 'continue analysis', max_hops: 2 },
      signingKey: privateKey,
      keyId: 'k1',
    })
    expect(superseding.chain).toEqual([])
    const extended = await extendChain(superseding, {
      agent_id: 'subagent', agent_type: 'sub-agent', action_summary: 'continue analysis', parent_hop: 0,
    }, privateKey)
    expect(await verifyToken(extended, { publicKey })).toEqual({ valid: true })
  })
})
