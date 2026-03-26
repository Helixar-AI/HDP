import { describe, it, expect } from 'vitest'
import { stripPrincipal, buildAuditSafe, redactPii } from '../../src/privacy/redactor.js'
import { isRetentionExpired, deleteToken } from '../../src/privacy/retention.js'
import { InMemoryTokenStore } from '../../src/transport/store.js'
import { storeToken, resolveToken } from '../../src/transport/reference.js'
import type { HdpToken } from '../../src/types/token.js'

const token: HdpToken = {
  hdp: '0.1',
  header: { token_id: 'abc', issued_at: 1000, expires_at: 2000, session_id: 's1', version: '0.1' },
  principal: { id: 'usr_sensitive', id_type: 'opaque', display_name: 'Alice' },
  scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
  chain: [],
  signature: { alg: 'Ed25519', kid: 'k', value: 'v', signed_fields: ['header', 'principal', 'scope'] },
}

describe('stripPrincipal', () => {
  it('removes the principal section entirely', () => {
    const stripped = stripPrincipal(token)
    expect('principal' in stripped).toBe(false)
  })

  it('preserves chain and scope', () => {
    const stripped = stripPrincipal(token)
    expect(stripped.scope).toEqual(token.scope)
    expect(stripped.chain).toEqual(token.chain)
  })
})

describe('buildAuditSafe', () => {
  it('retains only token_id from header and chain', () => {
    const safe = buildAuditSafe(token)
    expect(safe.token_id).toBe('abc')
    expect('principal' in safe).toBe(false)
    expect(Array.isArray(safe.chain)).toBe(true)
  })
})

describe('redactPii', () => {
  it('replaces principal.id with [REDACTED] and removes display_name', () => {
    const redacted = redactPii(token)
    expect(redacted.principal.id).toBe('[REDACTED]')
    expect(redacted.principal.display_name).toBeUndefined()
    // id_type is preserved
    expect(redacted.principal.id_type).toBe(token.principal.id_type)
    // scope and chain unchanged
    expect(redacted.scope).toEqual(token.scope)
  })
})

describe('isRetentionExpired', () => {
  it('returns true when retention period has passed', () => {
    const result = isRetentionExpired(token, { retentionMs: 100, now: token.header.issued_at + 200 })
    expect(result).toBe(true)
  })

  it('returns false when retention period has not passed', () => {
    const result = isRetentionExpired(token, { retentionMs: 10_000, now: token.header.issued_at + 200 })
    expect(result).toBe(false)
  })
})

describe('deleteToken', () => {
  it('removes token from store', async () => {
    const store = new InMemoryTokenStore()
    await storeToken(store, token)
    expect(await resolveToken(store, token.header.token_id)).not.toBeNull()
    await deleteToken(store, token.header.token_id)
    expect(await resolveToken(store, token.header.token_id)).toBeNull()
  })
})
