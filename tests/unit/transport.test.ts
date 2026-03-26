import { describe, it, expect } from 'vitest'
import { encodeHeader, decodeHeader } from '../../src/transport/http.js'
import { InMemoryTokenStore } from '../../src/transport/store.js'
import { storeToken, resolveToken } from '../../src/transport/reference.js'
import type { HdpToken } from '../../src/types/token.js'

const fakeToken: HdpToken = {
  hdp: '0.1',
  header: { token_id: 'abc', issued_at: 1000, expires_at: 2000, session_id: 's1', version: '0.1' },
  principal: { id: 'u', id_type: 'opaque' },
  scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
  chain: [],
  signature: { alg: 'Ed25519', kid: 'k', value: 'v', signed_fields: ['header', 'principal', 'scope'] },
}

describe('HTTP transport', () => {
  it('encodeHeader produces base64url string', () => {
    const encoded = encodeHeader(fakeToken)
    expect(typeof encoded).toBe('string')
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+=*$/)
  })

  it('decodeHeader round-trips the token', () => {
    const encoded = encodeHeader(fakeToken)
    const decoded = decodeHeader(encoded)
    expect(decoded).toEqual(fakeToken)
  })

  it('decodeHeader throws on invalid base64', () => {
    expect(() => decodeHeader('not!valid!base64!!!')).toThrow()
  })
})

describe('InMemoryTokenStore', () => {
  it('stores and retrieves a token by token_id', async () => {
    const store = new InMemoryTokenStore()
    await storeToken(store, fakeToken)
    const retrieved = await resolveToken(store, fakeToken.header.token_id)
    expect(retrieved).toEqual(fakeToken)
  })

  it('returns null for unknown token_id', async () => {
    const store = new InMemoryTokenStore()
    const result = await resolveToken(store, 'nonexistent')
    expect(result).toBeNull()
  })
})
