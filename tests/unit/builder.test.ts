import { describe, it, expect } from 'vitest'
import { TokenBuilder } from '../../src/token/builder.js'

describe('TokenBuilder', () => {
  it('builds a valid unsigned token with all required fields', () => {
    const token = new TokenBuilder('sess-001')
      .principal({ id: 'usr_abc', id_type: 'opaque' })
      .scope({
        intent: 'List files in /tmp',
        data_classification: 'internal',
        network_egress: false,
        persistence: false,
      })
      .expiresInMs(3600_000)
      .build()

    expect(token.hdp).toBe('0.1')
    expect(token.header.session_id).toBe('sess-001')
    expect(token.header.version).toBe('0.1')
    expect(typeof token.header.token_id).toBe('string')
    expect(token.header.expires_at).toBeGreaterThan(token.header.issued_at)
    expect(token.chain).toEqual([])
    expect(token.principal.id).toBe('usr_abc')
  })

  it('throws if principal is not set before build', () => {
    const builder = new TokenBuilder('s1').scope({
      intent: 'x', data_classification: 'public', network_egress: false, persistence: false
    })
    expect(() => builder.build()).toThrow()
  })

  it('throws if scope is not set before build', () => {
    const builder = new TokenBuilder('s1').principal({ id: 'u', id_type: 'uuid' })
    expect(() => builder.build()).toThrow()
  })
})
