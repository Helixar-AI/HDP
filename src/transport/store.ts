import type { HdpToken } from '../types/token.js'

export interface TokenStore {
  put(tokenId: string, token: HdpToken): Promise<void>
  get(tokenId: string): Promise<HdpToken | null>
  delete(tokenId: string): Promise<void>
}

export class InMemoryTokenStore implements TokenStore {
  private store = new Map<string, HdpToken>()

  async put(tokenId: string, token: HdpToken): Promise<void> {
    this.store.set(tokenId, token)
  }

  async get(tokenId: string): Promise<HdpToken | null> {
    return this.store.get(tokenId) ?? null
  }

  async delete(tokenId: string): Promise<void> {
    this.store.delete(tokenId)
  }
}
