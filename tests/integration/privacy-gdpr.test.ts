// tests/integration/privacy-gdpr.test.ts
import { describe, it, expect } from 'vitest'
import { issueToken } from '../../src/token/issuer.js'
import { extendChain } from '../../src/chain/extender.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { stripPrincipal, buildAuditSafe, redactPii } from '../../src/privacy/redactor.js'
import { isRetentionExpired, deleteToken } from '../../src/privacy/retention.js'
import { InMemoryTokenStore } from '../../src/transport/store.js'
import { storeToken, resolveToken } from '../../src/transport/reference.js'

async function fullToken() {
  const { privateKey } = await generateKeyPair()
  let token = await issueToken({
    sessionId: 'sess-privacy-01',
    principal: { id: 'usr_alice', id_type: 'opaque', display_name: 'Alice Smith' },
    scope: { intent: 'export quarterly report', data_classification: 'confidential', network_egress: false, persistence: true },
    signingKey: privateKey, keyId: 'k1',
  })
  token = await extendChain(token, { agent_id: 'report-agent', agent_type: 'orchestrator', action_summary: 'generate report', parent_hop: 0 }, privateKey)
  return token
}

describe('Privacy GDPR Integration', () => {
  it('stripPrincipal removes all principal PII before MCP transmission', async () => {
    const token = await fullToken()
    const stripped = stripPrincipal(token)
    const json = JSON.stringify(stripped)
    expect(json).not.toContain('alice')
    expect(json).not.toContain('Alice Smith')
    expect(json).not.toContain('usr_alice')
    // Chain and scope are still present
    expect(stripped.chain).toHaveLength(1)
    expect(stripped.scope.intent).toBe('export quarterly report')
  })

  it('buildAuditSafe produces safe log entry with only token_id, intent, chain summary', async () => {
    const token = await fullToken()
    const safe = buildAuditSafe(token)
    const json = JSON.stringify(safe)
    expect(json).not.toContain('usr_alice')
    expect(json).not.toContain('Alice Smith')
    expect(safe.token_id).toBe(token.header.token_id)
    expect(safe.intent).toBe('export quarterly report')
    expect(safe.chain[0].seq).toBe(1)
  })

  it('redactPii anonymizes principal fields while preserving structure', async () => {
    const token = await fullToken()
    const redacted = redactPii(token)
    expect(redacted.principal.id).toBe('[REDACTED]')
    expect(redacted.principal.display_name).toBeUndefined()
    // Token structure is preserved
    expect(redacted.scope).toEqual(token.scope)
    expect(redacted.chain).toHaveLength(token.chain.length)
  })

  it('deleteToken removes token from store (GDPR Article 17 erasure)', async () => {
    const token = await fullToken()
    const store = new InMemoryTokenStore()
    await storeToken(store, token)
    expect(await resolveToken(store, token.header.token_id)).not.toBeNull()
    await deleteToken(store, token.header.token_id)
    expect(await resolveToken(store, token.header.token_id)).toBeNull()
  })

  it('isRetentionExpired correctly determines when tokens should be purged', async () => {
    const token = await fullToken()
    const issuedAt = token.header.issued_at
    // 30-day retention policy
    expect(isRetentionExpired(token, { retentionMs: 30 * 24 * 60 * 60 * 1000, now: issuedAt + 1000 })).toBe(false)
    expect(isRetentionExpired(token, { retentionMs: 30 * 24 * 60 * 60 * 1000, now: issuedAt + 31 * 24 * 60 * 60 * 1000 })).toBe(true)
  })
})
