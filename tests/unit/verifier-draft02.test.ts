import { describe, expect, it } from 'vitest'
import { auditToken, computeTokenDigest, verifyToken } from '../../src/token/verifier.js'
import { extendChain } from '../../src/chain/extender.js'
import { issueToken } from '../../src/token/issuer.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

async function fixture() {
  const { privateKey, publicKey } = await generateKeyPair()
  const token = await issueToken({
    sessionId: 'draft-02-session',
    principal: { id: 'user', id_type: 'opaque' },
    scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
    signingKey: privateKey,
    keyId: 'draft-02-key',
  })
  return { token, privateKey, publicKey }
}

describe('draft -02 verifier semantics', () => {
  it('uses an inclusive issued_at and strict expires_at lifecycle interval', async () => {
    const { token, publicKey } = await fixture()

    expect((await verifyToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      now: token.header.issued_at,
    })).valid).toBe(true)

    const notYet = await verifyToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      now: token.header.issued_at - 1,
    })
    expect(notYet.error?.code).toBe('TOKEN_NOT_YET_VALID')

    const expired = await verifyToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      now: token.header.expires_at,
    })
    expect(expired.error?.code).toBe('TOKEN_EXPIRED')
  })

  it('checks local revocation and the signed final-hop presenter', async () => {
    const { token: issued, privateKey, publicKey } = await fixture()
    const token = await extendChain(issued, {
      agent_id: 'presenter-a',
      agent_type: 'orchestrator',
      action_summary: 'present',
      parent_hop: 0,
    }, privateKey)

    const revoked = await verifyToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      revokedTokenIds: new Set([token.header.token_id]),
    })
    expect(revoked.error?.code).toBe('TOKEN_REVOKED')

    const wrongPresenter = await verifyToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      expectedPresenterAgentId: 'presenter-b',
    })
    expect(wrongPresenter.error?.code).toBe('PRESENTER_MISMATCH')

    const callbackResult = await verifyToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      revokedTokenIds: id => id === 'other-token',
      expectedPresenterAgentId: 'presenter-a',
    })
    expect(callbackResult.valid).toBe(true)
  })

  it('rejects invalid parent hops and decreasing timestamps before hop signatures', async () => {
    const { token: issued, privateKey, publicKey } = await fixture()
    let token = await extendChain(issued, {
      agent_id: 'a',
      agent_type: 'orchestrator',
      action_summary: 'one',
      parent_hop: 0,
    }, privateKey)
    token = await extendChain(token, {
      agent_id: 'b',
      agent_type: 'sub-agent',
      action_summary: 'two',
      parent_hop: 1,
    }, privateKey)

    const badParent = {
      ...token,
      chain: token.chain.map((hop, index) => index === 1 ? { ...hop, parent_hop: 2 } : hop),
    }
    const parentResult = await verifyToken(badParent, {
      publicKey,
      currentSessionId: token.header.session_id,
    })
    expect(parentResult.error?.code).toBe('CHAIN_INTEGRITY')

    const badTime = {
      ...token,
      chain: token.chain.map((hop, index) => index === 1
        ? { ...hop, timestamp: token.chain[0].timestamp - 1 }
        : hop),
    }
    const timeResult = await verifyToken(badTime, {
      publicKey,
      currentSessionId: token.header.session_id,
    })
    expect(timeResult.error?.code).toBe('CHAIN_INTEGRITY')
  })

  it('reports integrity, current acceptance, and historical acceptance separately', async () => {
    const { token, publicKey } = await fixture()
    const digest = computeTokenDigest(token)
    const report = await auditToken(token, {
      publicKey,
      currentSessionId: token.header.session_id,
      now: token.header.issued_at,
      evidence: {
        tokenDigest: digest,
        sessionId: token.header.session_id,
        verifierId: 'verifier-a',
        evaluatedAt: token.header.issued_at,
        decision: 'accepted',
        authenticated: true,
        revoked: false,
        policyAccepted: true,
      },
    })

    expect(report.recordIntegrity.status).toBe('valid')
    expect(report.currentAcceptance.status).toBe('accepted')
    expect(report.historicalAcceptance.status).toBe('accepted')

    const withoutEvidence = await auditToken(token, { publicKey })
    expect(withoutEvidence.recordIntegrity.status).toBe('valid')
    expect(withoutEvidence.currentAcceptance.status).toBe('not_evaluated')
    expect(withoutEvidence.historicalAcceptance.status).toBe('indeterminate')
  })
})
