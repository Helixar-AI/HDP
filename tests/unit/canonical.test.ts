import { describe, it, expect } from 'vitest'
import { canonicalizeFields } from '../../src/crypto/canonical.js'

describe('canonicalizeFields', () => {
  it('produces deterministic output regardless of key insertion order', () => {
    const obj = { z: 1, a: 2, m: 3 }
    const result = canonicalizeFields(obj)
    expect(result).toBe('{"a":2,"m":3,"z":1}')
  })

  it('picks only the named fields from a token-shaped object', () => {
    const token = { hdp: '0.1', header: { token_id: 't1' }, principal: { id: 'u' }, scope: { intent: 'x' }, chain: [], signature: {} }
    const result = canonicalizeFields(token, ['header', 'principal', 'scope'])
    // Must be deterministic — call twice same result
    expect(canonicalizeFields(token, ['header', 'principal', 'scope'])).toBe(result)
    // Must only contain header, principal, scope — not hdp, chain, signature
    expect(result).toContain('"token_id"')
    expect(result).not.toContain('"chain"')
    expect(result).not.toContain('"signature"')
  })

  it('handles nested objects with unordered keys', () => {
    const obj = { b: { z: 1, a: 2 }, a: true }
    const result = canonicalizeFields(obj)
    expect(result).toBe('{"a":true,"b":{"a":2,"z":1}}')
  })
})
