import { afterEach, describe, expect, it, vi } from 'vitest'
import { extendChain } from '../../src/chain/extender.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { signHop } from '../../src/crypto/sign.js'
import { issueToken } from '../../src/token/issuer.js'
import { issueSupersedingToken } from '../../src/token/reauth.js'
import { auditToken, verifyToken } from '../../src/token/verifier.js'
import type { HopRecord } from '../../src/types/chain.js'
import type { HdpToken } from '../../src/types/token.js'

async function fixture(scope: HdpToken['scope'] = {
  intent: 'test', data_classification: 'public', network_egress: false, persistence: false,
}) {
  const { privateKey, publicKey } = await generateKeyPair()
  const token = await issueToken({
    sessionId: 'draft-03-session',
    principal: { id: 'user', id_type: 'opaque' },
    scope,
    signingKey: privateKey,
    keyId: 'draft-03-key',
  })
  return { token, privateKey, publicKey }
}

async function oneHop(token: HdpToken, privateKey: Uint8Array, agentType = 'orchestrator') {
  return extendChain(token, {
    agent_id: 'agent-a',
    agent_type: agentType,
    action_summary: 'recorded action',
    parent_hop: 0,
  }, privateKey)
}

async function overLimitToken(token: HdpToken, privateKey: Uint8Array): Promise<HdpToken> {
  const first = await oneHop(token, privateKey)
  const unsignedSecond = {
    seq: 2,
    agent_id: 'agent-b',
    agent_type: 'sub-agent',
    timestamp: first.chain[0].timestamp,
    action_summary: 'recorded follow-up',
    parent_hop: 1,
  }
  const hopSignature = await signHop(
    [...first.chain, unsignedSecond] as HopRecord[],
    first.signature.value,
    privateKey,
  )
  return {
    ...first,
    chain: [...first.chain, { ...unsignedSecond, hop_signature: hopSignature }],
  }
}

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('draft -03 integrity verification', () => {
  it('reports input validation failures at step 0', async () => {
    const { publicKey } = await fixture()
    const result = await verifyToken(null, { publicKey })

    expect(result).toMatchObject({ valid: false, failedStep: 0, error: { code: 'SCHEMA_INVALID' } })
  })

  it('rejects duplicate JSON member names before parsing serialized verifier input', async () => {
    const { token, publicKey } = await fixture()
    const duplicateJson = JSON.stringify(token).replace('"hdp":"0.1"', '"hdp":"0.1","hdp":"0.1"')
    const verification = await verifyToken(duplicateJson, { publicKey })
    const report = await auditToken(duplicateJson, { publicKey, sessionId: 'draft-03-session' })

    expect(verification).toMatchObject({ valid: false, failedStep: 0, error: { code: 'SCHEMA_INVALID' } })
    if (verification.valid) throw new Error('duplicate JSON input unexpectedly verified')
    expect(verification.error.message).toContain("duplicate JSON object member name 'hdp'")
    expect(report).toEqual({
      integrity: {
        status: 'invalid',
        failedStep: 0,
        error: expect.objectContaining({ code: 'SCHEMA_INVALID' }),
      },
      recordingPeriod: { status: 'not_checked' },
      session: { status: 'not_checked' },
      linkedRecords: { status: 'not_checked' },
      poh: { status: 'not_checked' },
    })

    // Parsing first discards the duplicate and reproduces the bypass this check prevents.
    expect(await verifyToken(JSON.parse(duplicateJson), { publicKey })).toEqual({ valid: true })
  })

  it('verifies a unique serialized token and maps JSON parse errors to step 0', async () => {
    const { token, publicKey } = await fixture()

    expect(await verifyToken(JSON.stringify(token), { publicKey })).toEqual({ valid: true })

    const malformedJson = `${JSON.stringify(token).slice(0, -1)},`
    const verification = await verifyToken(malformedJson, { publicKey })
    const report = await auditToken(malformedJson, { publicKey })

    expect(verification).toMatchObject({ valid: false, failedStep: 0, error: { code: 'SCHEMA_INVALID' } })
    expect(report).toMatchObject({
      integrity: { status: 'invalid', failedStep: 0, error: { code: 'SCHEMA_INVALID' } },
      recordingPeriod: { status: 'not_checked' },
      session: { status: 'not_checked' },
      linkedRecords: { status: 'not_checked' },
      poh: { status: 'not_checked' },
    })
  })

  it('reports unsupported and mismatched versions at step 1', async () => {
    const { token, publicKey } = await fixture()
    const unsupported = { ...token, hdp: '9.9', header: { ...token.header, version: '9.9' } }
    const unsupportedResult = await verifyToken(unsupported, { publicKey })
    expect(unsupportedResult).toMatchObject({ valid: false, failedStep: 1, error: { code: 'UNSUPPORTED_VERSION' } })

    const mismatched = { ...token, header: { ...token.header, version: '9.9' } }
    const mismatchResult = await verifyToken(mismatched, { publicKey })
    expect(mismatchResult).toMatchObject({ valid: false, failedStep: 1, error: { code: 'VERSION_MISMATCH' } })
  })

  it('reports a root signature failure at step 2', async () => {
    const { token } = await fixture()
    const { publicKey: wrongPublicKey } = await generateKeyPair()
    const result = await verifyToken(token, { publicKey: wrongPublicKey })
    const unsupportedAlgorithm = {
      ...token,
      signature: { ...token.signature, alg: 'HS256' },
    }
    const algorithmResult = await verifyToken(unsupportedAlgorithm, { publicKey: wrongPublicKey })

    expect(result).toMatchObject({ valid: false, failedStep: 2, error: { code: 'SIGNATURE_INVALID' } })
    expect(algorithmResult).toMatchObject({ valid: false, failedStep: 2, error: { code: 'SIGNATURE_INVALID' } })
  })

  it('reports hop sequence, parent, and timestamp structure failures at step 3', async () => {
    const { token, privateKey, publicKey } = await fixture()
    const first = await oneHop(token, privateKey)
    const recorded = await extendChain(first, {
      agent_id: 'agent-b', agent_type: 'sub-agent', action_summary: 'follow-up', parent_hop: 1,
    }, privateKey)
    const badSequence = {
      ...recorded,
      chain: recorded.chain.map((hop, index) => index === 0 ? { ...hop, seq: 2 } : hop),
    }
    const badParent = {
      ...recorded,
      chain: recorded.chain.map((hop, index) => index === 1 ? { ...hop, parent_hop: 2 } : hop),
    }
    const badTimestamp = {
      ...recorded,
      chain: recorded.chain.map((hop, index) => index === 1
        ? { ...hop, timestamp: recorded.chain[0].timestamp - 1 }
        : hop),
    }
    const results = await Promise.all([
      verifyToken(badSequence, { publicKey }),
      verifyToken(badParent, { publicKey }),
      verifyToken(badTimestamp, { publicKey }),
    ])

    for (const result of results) {
      expect(result).toMatchObject({ valid: false, failedStep: 3, error: { code: 'CHAIN_INTEGRITY' } })
    }
  })

  it('reports hop signature failures at step 4', async () => {
    const { token, privateKey, publicKey } = await fixture()
    const recorded = await oneHop(token, privateKey)
    const tampered = {
      ...recorded,
      chain: [{ ...recorded.chain[0], hop_signature: 'A'.repeat(86) }],
    }
    const result = await verifyToken(tampered, { publicKey })

    expect(result).toMatchObject({ valid: false, failedStep: 4, error: { code: 'SIGNATURE_INVALID' } })
  })

  it('reports chains deeper than max_hops at step 5', async () => {
    const { token, privateKey, publicKey } = await fixture({
      intent: 'test', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1,
    })
    const overLimit = await overLimitToken(token, privateKey)
    const result = await verifyToken(overLimit, { publicKey })

    expect(result).toMatchObject({ valid: false, failedStep: 5, error: { code: 'MAX_HOPS_EXCEEDED' } })
  })

  it('returns the same result when the wall clock moves far into the future', async () => {
    const { token, publicKey } = await fixture()
    const issuedResult = await verifyToken(token, { publicKey })

    vi.spyOn(Date, 'now').mockReturnValue(Number.MAX_SAFE_INTEGER)
    const futureResult = await verifyToken(token, { publicKey })

    expect(issuedResult).toEqual({ valid: true })
    expect(futureResult).toEqual({ valid: true })
    expect(futureResult).toEqual(issuedResult)
  })

  it('allows an expired record and reports every hop at or after expires_at', async () => {
    vi.useFakeTimers()
    const { privateKey, publicKey } = await generateKeyPair()
    const expiring = await issueFixtureAt(1_000, privateKey, 100)
    vi.setSystemTime(1_100)
    const first = await oneHop(expiring, privateKey)
    vi.setSystemTime(1_200)
    const second = await extendChain(first, {
      agent_id: 'agent-b', agent_type: 'sub-agent', action_summary: 'recorded follow-up', parent_hop: 1,
    }, privateKey)

    const verification = await verifyToken(second, { publicKey })
    const report = await auditToken(second, { publicKey })

    expect(expiring.header.expires_at).toBe(1_100)
    expect(verification).toEqual({ valid: true })
    expect(report.recordingPeriod).toEqual({ status: 'recorded_after_period', hopSeqs: [1, 2] })
  })

  it('keeps session mismatch out of integrity verification and reports it in audit', async () => {
    const { token, publicKey } = await fixture()
    const verification = await verifyToken(token, { publicKey })
    const report = await auditToken(token, { publicKey, sessionId: 'another-session' })

    expect(verification).toEqual({ valid: true })
    expect(report.session).toEqual({ status: 'mismatch' })
  })

  it('reports a linked relationship as unknown unless trusted context is supplied', async () => {
    const { token: original, privateKey, publicKey } = await fixture()
    const superseding = await issueSupersedingToken({ original, signingKey: privateKey, keyId: 'draft-03-key' })
    const unclassified = await auditToken(superseding, { publicKey })
    const classified = await auditToken(superseding, {
      publicKey,
      linkedRecordRelationship: 'supersession',
    })

    expect(unclassified.linkedRecords).toEqual({
      status: 'linked', parentTokenId: original.header.token_id, relationship: 'unknown',
    })
    expect(classified.linkedRecords).toEqual({
      status: 'linked', parentTokenId: original.header.token_id, relationship: 'supersession',
    })
  })

  it('reports a throwing PoH verifier as failed outside integrity', async () => {
    const { token: original, publicKey } = await fixture()
    const token = {
      ...original,
      principal: { ...original.principal, poh_credential: 'poh-credential' },
    }
    // The modified principal invalidates the root signature, but PoH remains a separate audit result.
    const report = await auditToken(token, {
      publicKey,
      pohVerifier: () => { throw new Error('verifier unavailable') },
    })

    expect(report.poh).toEqual({ status: 'failed' })
    expect(report.integrity.status).toBe('invalid')
  })

  it('marks every non-integrity result not_checked when input validation fails', async () => {
    const report = await auditToken({ malformed: true }, { sessionId: 'session' })

    expect(report).toEqual({
      integrity: { status: 'invalid', failedStep: 0, error: expect.objectContaining({ code: 'SCHEMA_INVALID' }) },
      recordingPeriod: { status: 'not_checked' },
      session: { status: 'not_checked' },
      linkedRecords: { status: 'not_checked' },
      poh: { status: 'not_checked' },
    })
  })

  it('reports a hand-pinned successful verification and audit shape', async () => {
    const { token, publicKey } = await fixture()

    expect(await verifyToken(token, { publicKey })).toEqual({ valid: true })
    expect(await auditToken(token, { publicKey, sessionId: 'draft-03-session' })).toEqual({
      integrity: { status: 'valid' },
      recordingPeriod: { status: 'within_period' },
      session: { status: 'match' },
      linkedRecords: { status: 'none' },
      poh: { status: 'not_checked' },
    })
  })

  it('marks integrity unverified when the issuer public key is not supplied', async () => {
    const { token } = await fixture()
    const report = await auditToken(token)

    expect(report.integrity).toEqual({ status: 'unverified' })
    expect(report.recordingPeriod).toEqual({ status: 'within_period' })
    expect(report.session).toEqual({ status: 'not_checked' })
    expect(report.linkedRecords).toEqual({ status: 'none' })
    expect(report.poh).toEqual({ status: 'not_checked' })
  })
})

async function issueFixtureAt(now: number, signingKey: Uint8Array, expiresInMs: number) {
  vi.setSystemTime(now)
  return issueToken({
    sessionId: 'draft-03-session',
    principal: { id: 'user', id_type: 'opaque' },
    scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
    signingKey,
    keyId: 'draft-03-key',
    expiresInMs,
  })
}
