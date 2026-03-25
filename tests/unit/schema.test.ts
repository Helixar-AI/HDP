import { describe, it, expect } from 'vitest'
import { validateToken } from '../../src/schema/validator.js'

describe('validateToken', () => {
  it('accepts a valid minimal token shape', () => {
    const token = {
      hdp: '0.1',
      header: { token_id: '550e8400-e29b-41d4-a716-446655440000', issued_at: 1000, expires_at: 2000, session_id: 's1', version: '0.1' },
      principal: { id: 'user1', id_type: 'opaque' },
      scope: { intent: 'do thing', data_classification: 'public', network_egress: false, persistence: false },
      chain: [],
      signature: { alg: 'Ed25519', kid: 'k1', value: 'abc', signed_fields: ['header', 'principal', 'scope'] }
    }
    expect(() => validateToken(token)).not.toThrow()
  })

  it('rejects token missing required principal.id', () => {
    const bad = { hdp: '0.1', header: {}, principal: { id_type: 'opaque' }, scope: {}, chain: [], signature: {} }
    expect(() => validateToken(bad)).toThrow('SCHEMA_INVALID')
  })

  it('rejects unknown data_classification', () => {
    const bad = {
      hdp: '0.1',
      header: { token_id: '550e8400-e29b-41d4-a716-446655440000', issued_at: 1000, expires_at: 2000, session_id: 's1', version: '0.1' },
      principal: { id: 'u', id_type: 'email' },
      scope: { intent: 'x', data_classification: 'top-secret', network_egress: false, persistence: false },
      chain: [],
      signature: { alg: 'Ed25519', kid: 'k', value: 'v', signed_fields: ['header', 'principal', 'scope'] }
    }
    expect(() => validateToken(bad)).toThrow('SCHEMA_INVALID')
  })
})
