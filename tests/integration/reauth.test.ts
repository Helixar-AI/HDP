import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { issueSupersedingToken } from '../../src/token/reauth.js'
import { auditToken, verifyToken } from '../../src/token/verifier.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('Superseding records (Section 6)', () => {
  it('signs the parent link and leaves the original record valid', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const original = await issueToken({
      sessionId: 'sess-superseding-01',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'initial task', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey, keyId: 'k1',
    })
    const superseding = await issueSupersedingToken({
      original,
      scope: { intent: 'continued task' },
      signingKey: privateKey,
      keyId: 'k1',
    })

    expect(superseding.header.parent_token_id).toBe(original.header.token_id)
    expect(superseding.scope.intent).toBe('continued task')
    expect(superseding.chain).toEqual([])
    expect(await verifyToken(original, { publicKey })).toEqual({ valid: true })
    expect(await verifyToken(superseding, { publicKey })).toEqual({ valid: true })
    expect((await auditToken(superseding, { publicKey })).linkedRecords).toEqual({
      status: 'linked', parentTokenId: original.header.token_id, relationship: 'unknown',
    })
  })
})
