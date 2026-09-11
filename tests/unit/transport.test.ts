import { describe, it, expect } from 'vitest'
import {
  encodeHeader,
  decodeHeader,
  HDP_HEADER,
  HDP_REF_HEADER,
  HDP_LEGACY_HEADER,
  HDP_LEGACY_REF_HEADER,
} from '../../src/transport/http.js'
import { InMemoryTokenStore } from '../../src/transport/store.js'
import { contentAddressedReference, storeToken, resolveToken } from '../../src/transport/reference.js'
import type { HdpToken } from '../../src/types/token.js'

const fakeToken: HdpToken = {
  hdp: '0.1',
  header: {
    token_id: '550e8400-e29b-41d4-a716-446655440000',
    issued_at: 1000,
    expires_at: 2000,
    session_id: 's1',
    version: '0.1',
  },
  principal: { id: 'u', id_type: 'opaque' },
  scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
  chain: [],
  signature: { alg: 'Ed25519', kid: 'k', value: 'A'.repeat(86) },
}

describe('HTTP transport', () => {
  it('advertises the standard draft -02 header names and labels X names as legacy', () => {
    expect(HDP_HEADER).toBe('HDP-Token')
    expect(HDP_REF_HEADER).toBe('HDP-Token-Ref')
    expect(HDP_LEGACY_HEADER).toBe('X-HDP-Token')
    expect(HDP_LEGACY_REF_HEADER).toBe('X-HDP-Token-Ref')
  })

  it('encodeHeader produces base64url string', () => {
    const encoded = encodeHeader(fakeToken)
    expect(typeof encoded).toBe('string')
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('decodeHeader round-trips the token', () => {
    const encoded = encodeHeader(fakeToken)
    const decoded = decodeHeader(encoded)
    expect(decoded).toEqual(fakeToken)
  })

  it('decodeHeader throws on invalid base64', () => {
    expect(() => decodeHeader('not!valid!base64!!!')).toThrow()
  })

  it('decodeHeader rejects duplicate object names before parsing', () => {
    const json = JSON.stringify(fakeToken).replace('"hdp":"0.1"', '"hdp":"0.1","hdp":"0.1"')
    const encoded = Buffer.from(json, 'utf8').toString('base64url')
    expect(() => decodeHeader(encoded)).toThrow('duplicate JSON object member name')
  })

  it('decodeHeader rejects invalid Unicode strings', () => {
    const json = JSON.stringify(fakeToken).replace('"intent":"test"', '"intent":"\\ud800"')
    const encoded = Buffer.from(json, 'utf8').toString('base64url')
    expect(() => decodeHeader(encoded)).toThrow('invalid Unicode')
  })

  it('decodeHeader validates the decoded token schema', () => {
    const json = JSON.stringify({ ...fakeToken, hdp: '9.9' })
    const encoded = Buffer.from(json, 'utf8').toString('base64url')
    expect(() => decodeHeader(encoded)).toThrow()
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
    const result = await resolveToken(store, '11111111-1111-4111-8111-111111111111')
    expect(result).toBeNull()
  })

  it('rejects references outside the UUID and sha256 forms', async () => {
    const store = new InMemoryTokenStore()
    await expect(resolveToken(store, 'opaque-reference')).rejects.toThrow('version 4 UUID')
  })

  it('resolves a token by its canonical SHA-256 content reference', async () => {
    const store = new InMemoryTokenStore()
    await storeToken(store, fakeToken)

    const reference = contentAddressedReference(fakeToken)
    expect(reference).toMatch(/^sha256:[A-Za-z0-9_-]{43}$/)
    await expect(resolveToken(store, reference)).resolves.toEqual(fakeToken)
  })

  it('rejects a content reference whose stored token digest does not match', async () => {
    const store = new InMemoryTokenStore()
    const reference = contentAddressedReference(fakeToken)
    await store.put(reference, { ...fakeToken, principal: { ...fakeToken.principal, id: 'different' } })

    await expect(resolveToken(store, reference)).rejects.toThrow('digest mismatch')
  })

  it('compares UUID references case-insensitively by UUID value', async () => {
    const store = new InMemoryTokenStore()
    await store.put(fakeToken.header.token_id, fakeToken)

    await expect(resolveToken(store, fakeToken.header.token_id.toUpperCase())).resolves.toEqual(fakeToken)
  })

  it('keeps writes immutable while allowing canonical idempotent retries', async () => {
    const store = new InMemoryTokenStore()
    await storeToken(store, fakeToken)
    await storeToken(store, { ...fakeToken, scope: { ...fakeToken.scope } })

    await expect(storeToken(store, {
      ...fakeToken,
      principal: { ...fakeToken.principal, id: 'different' },
    })).rejects.toThrow('different token')
  })

  it('rejects malformed content references before lookup', async () => {
    const store = new InMemoryTokenStore()
    await expect(resolveToken(store, 'sha256:not-a-digest')).rejects.toThrow('base64url')
  })
})
