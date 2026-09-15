import type { HdpToken } from '../types/token.js'
import {
  canonicalTokensEqual,
  normalizeStoreKey,
  snapshotToken,
  TokenReferenceIntegrityError,
} from './token-reference.js'

export interface TokenStore {
  put(tokenId: string, token: HdpToken): Promise<void>
  get(tokenId: string): Promise<HdpToken | null>
  delete(tokenId: string): Promise<void>
}

export class InMemoryTokenStore implements TokenStore {
  private store = new Map<string, HdpToken>()
  /** References remain write-once even after a caller deletes a snapshot. */
  private readonly writtenKeys = new Set<string>()

  async put(tokenId: string, token: HdpToken): Promise<void> {
    const key = normalizeStoreKey(tokenId)
    const snapshot = snapshotToken(token)
    const existing = this.store.get(key)

    if (existing !== undefined) {
      if (!canonicalTokensEqual(existing, snapshot)) {
        throw new TokenReferenceIntegrityError(`reference '${tokenId}' already identifies a different token`)
      }
      // Repeating an identical write is deliberately idempotent.
      return
    }

    if (this.writtenKeys.has(key)) {
      throw new TokenReferenceIntegrityError(`reference '${tokenId}' is immutable and cannot be rewritten`)
    }

    this.store.set(key, snapshot)
    this.writtenKeys.add(key)
  }

  async get(tokenId: string): Promise<HdpToken | null> {
    const token = this.store.get(normalizeStoreKey(tokenId))
    return token === undefined ? null : snapshotToken(token)
  }

  async delete(tokenId: string): Promise<void> {
    const key = normalizeStoreKey(tokenId)
    if (this.store.has(key)) {
      this.store.delete(key)
      // Keep the write-once marker so a deleted reference cannot be rebound
      // to a different immutable snapshot later.
      this.writtenKeys.add(key)
    }
  }
}
