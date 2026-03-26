// tests/integration/transport-roundtrip.test.ts
import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { verifyToken } from '../../src/token/verifier.js'
import { encodeHeader, decodeHeader } from '../../src/transport/http.js'
import { InMemoryTokenStore } from '../../src/transport/store.js'
import { storeToken, resolveToken } from '../../src/transport/reference.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('Transport Roundtrip', () => {
  it('token survives HTTP header encode → decode → verify', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-http-01',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'api call', data_classification: 'internal', network_egress: true, persistence: false },
      signingKey: privateKey, keyId: 'k1',
    })
    const encoded = encodeHeader(token)
    const decoded = decodeHeader(encoded)
    const result = await verifyToken(decoded, { publicKey, currentSessionId: 'sess-http-01' })
    expect(result.valid).toBe(true)
  })

  it('token survives store → retrieve → verify (token-by-reference)', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const token = await issueToken({
      sessionId: 'sess-ref-01',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'ref task', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey, keyId: 'k1',
    })
    const store = new InMemoryTokenStore()
    const tokenId = await storeToken(store, token)
    const retrieved = await resolveToken(store, tokenId)
    expect(retrieved).not.toBeNull()
    const result = await verifyToken(retrieved!, { publicKey, currentSessionId: 'sess-ref-01' })
    expect(result.valid).toBe(true)
  })
})
