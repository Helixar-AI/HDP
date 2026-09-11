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
      signature: { alg: 'Ed25519', kid: 'k1', value: 'A'.repeat(86), signed_fields: ['header', 'principal', 'scope'] }
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

  it('rejects timestamps outside the exact JSON integer range', () => {
    const bad = {
      hdp: '0.1',
      header: { token_id: '550e8400-e29b-41d4-a716-446655440000', issued_at: -1, expires_at: 2000, session_id: 's1', version: '0.1' },
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', data_classification: 'public', network_egress: false, persistence: false },
      chain: [],
      signature: { alg: 'Ed25519', kid: 'k', value: 'A'.repeat(86) },
    }
    expect(() => validateToken(bad)).toThrow('SCHEMA_INVALID')
  })

  it('rejects expires_at that is not greater than issued_at', () => {
    const bad = {
      hdp: '0.1',
      header: { token_id: '550e8400-e29b-41d4-a716-446655440000', issued_at: 2000, expires_at: 2000, session_id: 's1', version: '0.1' },
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', data_classification: 'public', network_egress: false, persistence: false },
      chain: [],
      signature: { alg: 'Ed25519', kid: 'k', value: 'v' },
    }
    expect(() => validateToken(bad)).toThrow('SCHEMA_INVALID')
  })

  it('rejects non-v4 token identifiers', () => {
    const bad = {
      hdp: '0.1',
      header: { token_id: '550e8400-e29b-11d4-a716-446655440000', issued_at: 1000, expires_at: 2000, session_id: 's1', version: '0.1' },
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', data_classification: 'public', network_egress: false, persistence: false },
      chain: [],
      signature: { alg: 'Ed25519', kid: 'k', value: 'v' },
    }
    expect(() => validateToken(bad)).toThrow('SCHEMA_INVALID')
  })

  it('accepts an extension principal id_type with the x- prefix', () => {
    const token = {
      hdp: '0.1',
      header: { token_id: '550e8400-e29b-41d4-a716-446655440000', issued_at: 1000, expires_at: 2000, session_id: 's1', version: '0.1' },
      principal: { id: 'tenant-user-7', id_type: 'x-tenant-subject' },
      scope: { intent: 'x', data_classification: 'public', network_egress: false, persistence: false },
      chain: [],
      signature: { alg: 'Ed25519', kid: 'k', value: 'A'.repeat(86) },
    }
    expect(() => validateToken(token)).not.toThrow()
  })
})
