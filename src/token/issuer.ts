import { TokenBuilder } from './builder.js'
import { signRoot } from '../crypto/sign.js'
import type { HdpPrincipal, HdpScope, HdpToken } from '../types/token.js'

export interface IssueTokenOptions {
  sessionId: string
  principal: HdpPrincipal
  scope: HdpScope
  signingKey: Uint8Array
  keyId: string
  /** Issuer-selected lifetime. The SDK currently falls back to 24h; HDP defines no protocol default. */
  expiresInMs?: number
}

export async function issueToken(opts: IssueTokenOptions): Promise<HdpToken> {
  const unsigned = new TokenBuilder(opts.sessionId)
    .principal(opts.principal)
    .scope(opts.scope)
    .expiresInMs(opts.expiresInMs ?? 24 * 60 * 60 * 1000)
    .build()

  const signature = await signRoot(unsigned as any, opts.signingKey, opts.keyId)
  return { ...unsigned, signature }
}
