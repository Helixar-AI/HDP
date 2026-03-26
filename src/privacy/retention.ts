import type { HdpToken } from '../types/token.js'
import type { TokenStore } from '../transport/store.js'

export interface RetentionOptions {
  retentionMs: number
  now?: number
}

export function isRetentionExpired(token: HdpToken, opts: RetentionOptions): boolean {
  const now = opts.now ?? Date.now()
  return now > token.header.issued_at + opts.retentionMs
}

/**
 * Deletes a token from the store — implements GDPR Article 17 erasure obligation.
 * Callers are responsible for also deleting from backup stores and cache layers
 * per spec Section 13.4 MUST.
 */
export async function deleteToken(store: TokenStore, tokenId: string): Promise<void> {
  await store.delete(tokenId)
}
