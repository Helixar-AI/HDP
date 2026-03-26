/**
 * KeyRegistry — lightweight in-process key store for mapping kid → publicKey.
 *
 * Intended for agent frameworks without existing PKI infrastructure.
 * For production use, back this with a secrets manager or a well-known endpoint.
 *
 * Well-known endpoint format (serve at /.well-known/hdp-keys.json):
 *   { "keys": [ { "kid": "...", "alg": "Ed25519", "pub": "<base64url>" } ] }
 */
import { importPublicKey, exportPublicKey } from './keys.js'

export interface WellKnownKey {
  kid: string
  alg: 'Ed25519'
  pub: string // base64url-encoded public key
}

export interface WellKnownKeyDocument {
  keys: WellKnownKey[]
}

export class KeyRegistry {
  private keys = new Map<string, Uint8Array>()

  /**
   * Register a public key by kid.
   * @throws {Error} if the key is not a valid 32-byte Ed25519 public key.
   * @note Silently overwrites any previously registered key for the same kid.
   *       To rotate a key safely, call `revoke(kid)` first.
   */
  register(kid: string, publicKey: Uint8Array): void {
    if (publicKey.length !== 32) {
      throw new Error(`Invalid Ed25519 public key for kid '${kid}': expected 32 bytes, got ${publicKey.length}`)
    }
    this.keys.set(kid, publicKey)
  }

  /** Resolve a kid to its public key. Returns null if not found. */
  resolve(kid: string): Uint8Array | null {
    return this.keys.get(kid) ?? null
  }

  /** Remove a key from the registry. */
  revoke(kid: string): void {
    this.keys.delete(kid)
  }

  /** List all registered kids. */
  kids(): string[] {
    return [...this.keys.keys()]
  }

  /**
   * Export the registry as a well-known key document.
   * Suitable for serving at /.well-known/hdp-keys.json
   */
  exportWellKnown(): WellKnownKeyDocument {
    return {
      keys: [...this.keys.entries()].map(([kid, pub]) => ({
        kid,
        alg: 'Ed25519' as const,
        pub: exportPublicKey(pub),
      })),
    }
  }

  /**
   * Load from a well-known key document (e.g. fetched from /.well-known/hdp-keys.json).
   * Adds all keys to the registry; does not clear existing entries.
   * @throws {Error} if any entry has an unrecognized algorithm or an invalid public key.
   */
  loadWellKnown(doc: WellKnownKeyDocument): void {
    for (const entry of doc.keys) {
      if (entry.alg !== 'Ed25519') {
        throw new Error(`Unsupported algorithm '${entry.alg}' for kid '${entry.kid}': only Ed25519 is supported`)
      }
      const pubKey = importPublicKey(entry.pub)
      if (pubKey.length !== 32) {
        throw new Error(`Invalid Ed25519 public key for kid '${entry.kid}': expected 32 bytes, got ${pubKey.length}`)
      }
      this.keys.set(entry.kid, pubKey)
    }
  }
}
