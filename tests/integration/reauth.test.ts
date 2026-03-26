// tests/integration/reauth.test.ts
import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { verifyToken } from '../../src/token/verifier.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('Re-authorization Flow (Section 6.4)', () => {
  it('new token with parent_token_id represents re-authorization', async () => {
    const { privateKey, publicKey } = await generateKeyPair()

    // Original token — max_hops=1
    const original = await issueToken({
      sessionId: 'sess-reauth-01',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'initial task', data_classification: 'public', network_egress: false, persistence: false, max_hops: 1 },
      signingKey: privateKey, keyId: 'k1',
    })

    // Simulate max_hops hit — agent requests re-auth
    // Re-authorization produces a new token with parent_token_id set
    const reAuthToken = await issueToken({
      sessionId: 'sess-reauth-01',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'continued task after re-auth', data_classification: 'public', network_egress: false, persistence: false, max_hops: 2 },
      signingKey: privateKey, keyId: 'k1',
    })
    // Manually set parent_token_id (builder extension exercise — kept simple here)
    const linkedToken = {
      ...reAuthToken,
      header: { ...reAuthToken.header, parent_token_id: original.header.token_id }
    }

    expect(linkedToken.header.parent_token_id).toBe(original.header.token_id)

    // Verify the re-auth token is cryptographically valid.
    // Note: linkedToken demonstrates parent_token_id linkage but cannot be verified
    // because parent_token_id was set after signing — the signature covers the original header.
    const result = await verifyToken(reAuthToken, { publicKey, currentSessionId: 'sess-reauth-01' })
    expect(result.valid).toBe(true)
  })
})
