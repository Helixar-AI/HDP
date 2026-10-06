/** Joint-approval audit helpers for linked HDP records. */
import { HdpChainIntegrityError, HdpError } from '../types/errors.js'
import type { HdpToken } from '../types/token.js'
import { verifyToken } from './verifier.js'
import type { VerificationResult } from './verifier.js'

export interface PrincipalChainEntry {
  token: HdpToken
  /** Ed25519 public key for this token's issuer. */
  publicKey: Uint8Array
}

export interface PrincipalChainVerificationResult {
  valid: boolean
  /** Meaning established by trusted application context, not by the parent link alone. */
  relationship: 'joint_approval' | 'unknown'
  /** Index of the first token or relationship check that failed, if any. */
  failedAt?: number
  error?: HdpError
  /** Integrity result for each token in chain order. */
  results: VerificationResult[]
}

export interface PrincipalChainVerificationOptions {
  relationshipContext?: {
    type: 'joint_approval'
    /** The application has authenticated and integrity-protected this context. */
    authenticated: boolean
  }
}

/**
 * Audit an ordered chain of independently signed records.
 *
 * Each token's integrity is checked first. The linked records must then have
 * matching parent_token_id and session_id values. Relationship meaning is
 * joint approval only when authenticated application context supplies it.
 */
export async function verifyPrincipalChain(
  chain: PrincipalChainEntry[],
  opts: PrincipalChainVerificationOptions = {},
): Promise<PrincipalChainVerificationResult> {
  const trustedJointApproval = opts.relationshipContext?.type === 'joint_approval'
    && opts.relationshipContext.authenticated

  if (chain.length === 0) {
    return {
      valid: false,
      relationship: 'unknown',
      results: [],
      error: new HdpChainIntegrityError('principal chain must contain at least one entry'),
    }
  }

  const results: VerificationResult[] = []
  for (let i = 0; i < chain.length; i++) {
    const { token, publicKey } = chain[i]
    const result = await verifyToken(token, { publicKey })
    results.push(result)
    if (!result.valid) {
      return { valid: false, relationship: 'unknown', failedAt: i, error: result.error, results }
    }
  }

  const rootSessionId = chain[0].token.header.session_id
  for (let i = 1; i < chain.length; i++) {
    const previous = chain[i - 1].token
    const current = chain[i].token
    if (current.header.parent_token_id !== previous.header.token_id) {
      const error = new HdpChainIntegrityError(
        `token at index ${i} has parent_token_id '${current.header.parent_token_id}', expected '${previous.header.token_id}'`,
      )
      return { valid: false, relationship: 'unknown', failedAt: i, error, results }
    }

    if (current.header.session_id !== rootSessionId) {
      const error = new HdpError(
        `token at index ${i} has session_id '${current.header.session_id}', expected '${rootSessionId}'`,
        'SESSION_MISMATCH',
      )
      return { valid: false, relationship: 'unknown', failedAt: i, error, results }
    }
  }

  return {
    valid: true,
    relationship: trustedJointApproval && chain.length > 1 ? 'joint_approval' : 'unknown',
    results,
  }
}

// ---------------------------------------------------------------------------
// HDP v0.2 Preview Types
// ---------------------------------------------------------------------------

/**
 * @experimental HDP v0.2 preview; not implemented in the signing pipeline.
 *
 * Co-authorization request: two principals simultaneously authorize a
 * high-risk action by each signing the same token payload. This requires a
 * threshold signing scheme such as FROST or Schnorr multisignature.
 */
export interface CoAuthorizationRequest {
  /** All co-authorizing principals. */
  co_principals: Array<{
    id: string
    id_type: string
    display_name?: string
  }>
  /** Required number of signatures to consider the token valid. */
  threshold: number
  /** One signature per co-principal, in the same order as co_principals. */
  co_signatures: string[]
}
