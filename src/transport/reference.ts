import type { HdpToken } from '../types/token.js'
import type { TokenStore } from './store.js'

export async function storeToken(store: TokenStore, token: HdpToken): Promise<string> {
  await store.put(token.header.token_id, token)
  return token.header.token_id
}

export async function resolveToken(store: TokenStore, tokenId: string): Promise<HdpToken | null> {
  return store.get(tokenId)
}
