import { TokenBuilder } from './builder.js'
import { signRoot } from '../crypto/sign.js'
import type { HdpToken, HdpPrincipal, HdpScope, UnsignedToken } from '../types/token.js'

export interface SupersedingTokenOptions {
  /** The record being superseded; its token_id becomes parent_token_id. */
  original: HdpToken
  /** Scope for the new record. Defaults to the original scope. */
  scope?: Partial<HdpScope>
  /** Session for the new record. Defaults to the original session_id. */
  sessionId?: string
  /** Principal for the new record. Defaults to the original principal. */
  principal?: HdpPrincipal
  /** Issuer-selected lifetime. Omission uses the SDK's 24-hour fallback; HDP defines no protocol default. */
  expiresInMs?: number
  /** Ed25519 private key for signing the new record. */
  signingKey: Uint8Array
  /** Key ID for the signature. */
  keyId: string
}

export type SupersedingToken = HdpToken & {
  header: HdpToken['header'] & { parent_token_id: string }
}

/**
 * Issue a new record that supersedes an existing token.
 *
 * The superseding record has a new token_id and timestamps, inherits the
 * session, principal, and scope unless overridden, and starts with an empty
 * chain. Supersession adds a record; it does not revoke or invalidate the
 * original token.
 */
export async function issueSupersedingToken(opts: SupersedingTokenOptions): Promise<SupersedingToken> {
  const { original, signingKey, keyId } = opts
  const sessionId = opts.sessionId ?? original.header.session_id
  const principal = opts.principal ?? original.principal
  const scope: HdpScope = { ...original.scope, ...opts.scope }

  const unsigned = new TokenBuilder(sessionId)
    .principal(principal)
    .scope(scope)
    .expiresInMs(opts.expiresInMs ?? 24 * 60 * 60 * 1000)
    .build()

  const unsignedWithParent: UnsignedToken = {
    ...unsigned,
    header: {
      ...unsigned.header,
      parent_token_id: original.header.token_id,
    },
  }

  const signature = await signRoot(unsignedWithParent, signingKey, keyId)
  return { ...unsignedWithParent, signature } as SupersedingToken
}

/** @deprecated Use SupersedingTokenOptions. */
export type ReAuthOptions = SupersedingTokenOptions

/** @deprecated Use SupersedingToken. */
export type ReAuthToken = SupersedingToken

/** @deprecated Use issueSupersedingToken. */
export const issueReAuthToken: typeof issueSupersedingToken = issueSupersedingToken
