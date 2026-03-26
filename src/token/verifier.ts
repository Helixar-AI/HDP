import { verifyRoot, verifyHop } from '../crypto/verify.js'
import type { HdpToken } from '../types/token.js'
import type { HdpError } from '../types/errors.js'
import {
  HdpTokenExpiredError,
  HdpSignatureInvalidError,
  HdpChainIntegrityError,
  HdpSessionMismatchError,
  HdpMaxHopsExceededError,
} from '../types/errors.js'

export interface VerificationOptions {
  publicKey: Uint8Array
  currentSessionId: string
  /** If omitted, current Date.now() is used */
  now?: number
  /**
   * Optional PoH verifier callback (spec Section 7.3 step 7).
   * If provided and the token has principal.poh_credential, this is called to verify it.
   * Returns true if credential is valid, false otherwise.
   */
  pohVerifier?: (credential: string) => Promise<boolean>
}

export interface VerificationResult {
  valid: boolean
  error?: HdpError
}

const SUPPORTED_VERSIONS = new Set(['0.1'])

export async function verifyToken(
  token: HdpToken,
  opts: VerificationOptions
): Promise<VerificationResult> {
  const now = opts.now ?? Date.now()

  // Step 1: Check version
  if (!SUPPORTED_VERSIONS.has(token.hdp)) {
    return { valid: false, error: new HdpSignatureInvalidError(`Unsupported version: ${token.hdp}`) }
  }

  // Step 2: Check expiry
  if (token.header.expires_at < now) {
    return { valid: false, error: new HdpTokenExpiredError(token.header.expires_at) }
  }

  // Step 3: Verify root signature
  const rootValid = await verifyRoot(token as any, token.signature, opts.publicKey)
  if (!rootValid) {
    return { valid: false, error: new HdpSignatureInvalidError('root signature verification failed') }
  }

  // Steps 4 + 5: Verify hop signatures (MUST be present per Rule 6) and seq contiguity
  const chain = token.chain
  for (let i = 0; i < chain.length; i++) {
    const hop = chain[i]
    if (hop.seq !== i + 1) {
      return { valid: false, error: new HdpChainIntegrityError(`seq gap at position ${i}: expected ${i + 1}, got ${hop.seq}`) }
    }
    // Spec Section 6.3 Rule 6: hop_signature MUST be present — absence is a protocol violation
    if (!hop.hop_signature) {
      return { valid: false, error: new HdpChainIntegrityError(`hop ${hop.seq} is missing required hop_signature`) }
    }
    const cumulative = chain.slice(0, i + 1)
    const hopValid = await verifyHop(cumulative, token.signature.value, hop.hop_signature, opts.publicKey)
    if (!hopValid) {
      return { valid: false, error: new HdpSignatureInvalidError(`hop ${hop.seq} signature verification failed`) }
    }
  }

  // Step 6: max_hops check
  if (token.scope.max_hops !== undefined && chain.length > token.scope.max_hops) {
    return { valid: false, error: new HdpMaxHopsExceededError(token.scope.max_hops) }
  }

  // Section 12.7 MUST: session_id replay defense (checked before PoH to avoid unnecessary endpoint calls)
  if (token.header.session_id !== opts.currentSessionId) {
    return { valid: false, error: new HdpSessionMismatchError() }
  }

  // Step 7 (spec Section 7.3): PoH credential verification (if present and verifier provided)
  if (token.principal.poh_credential && opts.pohVerifier) {
    const pohValid = await opts.pohVerifier(token.principal.poh_credential)
    if (!pohValid) {
      return { valid: false, error: new HdpSignatureInvalidError('PoH credential verification failed') }
    }
  }

  return { valid: true }
}
