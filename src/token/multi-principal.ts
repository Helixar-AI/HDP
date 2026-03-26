// src/token/multi-principal.ts
/**
 * Multi-principal delegation utilities.
 *
 * HDP v0.1 supports one principal per token. For actions that require
 * joint authorization from two humans, the pattern is sequential token
 * chaining: Human A issues T1; Human B issues T2 with parent_token_id: T1.
 *
 * verifyPrincipalChain() walks the parent_token_id chain and verifies
 * each token's root signature against the corresponding public key.
 *
 * For a formal co-authorization primitive (simultaneous multi-sig),
 * see CoAuthorizationRequest — planned for HDP v0.2.
 */
import { verifyToken } from './verifier.js'
import type { HdpToken } from '../types/token.js'
import type { VerificationOptions, VerificationResult } from './verifier.js'
import type { HdpError } from '../types/errors.js'

export interface PrincipalChainEntry {
  token: HdpToken
  /** Ed25519 public key for this token's issuer. */
  publicKey: Uint8Array
}

export interface PrincipalChainVerificationResult {
  valid: boolean
  /** Index of the first token that failed verification, if any. */
  failedAt?: number
  error?: HdpError
  /** Individual result per token in the chain order. */
  results: VerificationResult[]
}

/**
 * Verify a chain of tokens where each token's parent_token_id
 * points to the previous token's token_id.
 *
 * Validates:
 * 1. Each token passes full 7-step verification (root sig, hops, expiry, session_id)
 * 2. parent_token_id links are correct (T[i].parent_token_id === T[i-1].token_id)
 * 3. All tokens share the same session_id
 *
 * @param chain - Ordered array from root (T1) to leaf (Tn), each with its issuer's public key
 * @param opts  - Verification options applied to all tokens (session_id, now, pohVerifier)
 */
export async function verifyPrincipalChain(
  chain: PrincipalChainEntry[],
  opts: Omit<VerificationOptions, 'publicKey'>
): Promise<PrincipalChainVerificationResult> {
  if (chain.length === 0) {
    return { valid: false, results: [], error: undefined }
  }

  const results: VerificationResult[] = []

  for (let i = 0; i < chain.length; i++) {
    const { token, publicKey } = chain[i]

    // Verify parent_token_id linkage (from index 1 onwards)
    if (i > 0) {
      const expectedParent = chain[i - 1].token.header.token_id
      const actualParent = (token.header as unknown as Record<string, unknown>).parent_token_id
      if (actualParent !== expectedParent) {
        const err = {
          name: 'HdpError',
          message: `CHAIN_INTEGRITY: token at index ${i} has parent_token_id '${actualParent}', expected '${expectedParent}'`,
          code: 'CHAIN_INTEGRITY',
        } as unknown as HdpError
        return { valid: false, failedAt: i, error: err, results }
      }
    }

    const result = await verifyToken(token, { ...opts, publicKey })
    results.push(result)

    if (!result.valid) {
      return { valid: false, failedAt: i, error: result.error, results }
    }
  }

  return { valid: true, results }
}

// ---------------------------------------------------------------------------
// HDP v0.2 Preview Types
// ---------------------------------------------------------------------------

/**
 * @experimental HDP v0.2 — not yet implemented in the signing pipeline.
 *
 * Co-authorization request: two principals simultaneously authorize a
 * high-risk action by each signing the same token payload.
 * Requires a threshold signing scheme (e.g. FROST / Schnorr multisig).
 */
export interface CoAuthorizationRequest {
  /** All co-authorizing principals. */
  co_principals: Array<{
    id: string
    id_type: string
    display_name?: string
  }>
  /**
   * Required number of signatures to consider the token valid.
   * For joint authorization of two humans: threshold = 2.
   */
  threshold: number
  /** One signature per co-principal, in the same order as co_principals. */
  co_signatures: string[] // base64url Ed25519 signatures
}
