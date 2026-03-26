import { describe, it, expect } from 'vitest'
import { generateKeyPair, exportPublicKey, importPublicKey } from '../../src/crypto/keys.js'

describe('key management', () => {
  it('generateKeyPair returns privateKey and publicKey as Uint8Array', async () => {
    const kp = await generateKeyPair()
    expect(kp.privateKey).toBeInstanceOf(Uint8Array)
    expect(kp.publicKey).toBeInstanceOf(Uint8Array)
    expect(kp.privateKey).toHaveLength(32)
    expect(kp.publicKey).toHaveLength(32)
  })

  it('exportPublicKey returns base64url string', async () => {
    const kp = await generateKeyPair()
    const exported = exportPublicKey(kp.publicKey)
    expect(typeof exported).toBe('string')
    expect(exported).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('importPublicKey round-trips with exportPublicKey', async () => {
    const kp = await generateKeyPair()
    const exported = exportPublicKey(kp.publicKey)
    const imported = importPublicKey(exported)
    expect(imported).toEqual(kp.publicKey)
  })
})
