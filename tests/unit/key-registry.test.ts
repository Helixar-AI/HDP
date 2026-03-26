import { describe, it, expect } from 'vitest'
import { KeyRegistry } from '../../src/crypto/registry.js'
import { generateKeyPair } from '../../src/crypto/keys.js'

describe('KeyRegistry', () => {
  it('registers and resolves a key by kid', async () => {
    const { publicKey } = await generateKeyPair()
    const registry = new KeyRegistry()
    registry.register('key-001', publicKey)
    const resolved = registry.resolve('key-001')
    expect(resolved).not.toBeNull()
    expect(resolved).toEqual(publicKey)
  })

  it('returns null for unknown kid', () => {
    const registry = new KeyRegistry()
    expect(registry.resolve('missing')).toBeNull()
  })

  it('revokes a key', async () => {
    const { publicKey } = await generateKeyPair()
    const registry = new KeyRegistry()
    registry.register('k1', publicKey)
    registry.revoke('k1')
    expect(registry.resolve('k1')).toBeNull()
  })

  it('exports to well-known format and reloads', async () => {
    const { publicKey } = await generateKeyPair()
    const registry = new KeyRegistry()
    registry.register('k1', publicKey)
    const doc = registry.exportWellKnown()
    expect(doc.keys).toHaveLength(1)
    expect(doc.keys[0].kid).toBe('k1')
    expect(doc.keys[0].alg).toBe('Ed25519')

    const registry2 = new KeyRegistry()
    registry2.loadWellKnown(doc)
    expect(registry2.resolve('k1')).toEqual(publicKey)
  })

  it('lists all registered kids', async () => {
    const { publicKey } = await generateKeyPair()
    const registry = new KeyRegistry()
    registry.register('k1', publicKey)
    registry.register('k2', publicKey)
    expect(registry.kids().sort()).toEqual(['k1', 'k2'])
  })
})
