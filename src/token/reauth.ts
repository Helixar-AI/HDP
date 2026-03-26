/**
 * Re-authorization utilities for long-running and streaming sessions.
 *
 * When a session's scope needs to evolve — because max_hops is exhausted,
 * the task has expanded, or a high-risk action requires fresh human approval —
 * issue a new token with parent_token_id pointing to the original.
 *
 * Each scope change is a distinct human authorization event.
 * The audit trail of parent_token_id chains documents how scope evolved.
 */
import { TokenBuilder } from './builder.js'
import { signRoot } from '../crypto/sign.js'
import type { HdpToken, HdpPrincipal, HdpScope } from '../types/token.js'

export interface ReAuthOptions {
  /** The token being superseded (its token_id becomes parent_token_id). */
  original: HdpToken
  /** New scope for the re-authorized session. Defaults to original scope if omitted. */
  scope?: Partial<HdpScope>
  /** New session ID, if the session is being rotated. Defaults to original session ID. */
  sessionId?: string
  /** Override principal. Defaults to original principal. */
  principal?: HdpPrincipal
  /** Token lifetime in ms. Defaults to 24h. */
  expiresInMs?: number
  /** Ed25519 private key for signing the new token. */
  signingKey: Uint8Array
  /** Key ID for the signature. */
  keyId: string
}

export interface ReAuthToken extends HdpToken {
  header: HdpToken['header'] & { parent_token_id: string }
}

/**
 * Issue a re-authorization token that supersedes an existing token.
 *
 * The new token:
 * - Has a fresh token_id, issued_at, and expires_at
 * - Records parent_token_id pointing to the original token
 * - Inherits scope, principal, and session_id from the original (unless overridden)
 * - Starts with an empty chain (hop 0)
 *
 * Use this when:
 * - max_hops is exhausted and the task must continue
 * - Scope needs to expand (new tools, new resources)
 * - A high-risk action requires fresh human confirmation
 * - The session token is approaching expiry
 */
export async function issueReAuthToken(opts: ReAuthOptions): Promise<ReAuthToken> {
  const { original, signingKey, keyId } = opts
  const sessionId = opts.sessionId ?? original.header.session_id
  const principal = opts.principal ?? original.principal
  const scope: HdpScope = { ...original.scope, ...opts.scope }

  const unsigned = new TokenBuilder(sessionId)
    .principal(principal)
    .scope(scope)
    .expiresInMs(opts.expiresInMs ?? 24 * 60 * 60 * 1000)
    .build()

  // Attach parent_token_id before signing so it's covered by the root signature
  const unsignedWithParent = {
    ...unsigned,
    header: {
      ...unsigned.header,
      parent_token_id: original.header.token_id,
    },
  }

  const signature = await signRoot(unsignedWithParent as any, signingKey, keyId)
  return { ...unsignedWithParent, signature } as ReAuthToken
}
