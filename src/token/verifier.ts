import { verifyRoot, verifyHop } from '../crypto/verify.js'
import { validateToken } from '../schema/validator.js'
import { contentAddressedReference } from '../transport/token-reference.js'
import type { HopRecord } from '../types/chain.js'
import type { HdpToken } from '../types/token.js'
import { HdpError } from '../types/errors.js'
import {
  HdpSchemaError,
  HdpTokenExpiredError,
  HdpTokenNotYetValidError,
  HdpTokenRevokedError,
  HdpSignatureInvalidError,
  HdpChainIntegrityError,
  HdpSessionMismatchError,
  HdpPresenterMismatchError,
  HdpMaxHopsExceededError,
  HdpUnsupportedVersionError,
  HdpVersionMismatchError,
} from '../types/errors.js'

/** A local revocation source. It is intentionally not a network client. */
export type RevocationState =
  | ReadonlySet<string>
  | ((tokenId: string) => boolean | Promise<boolean>)

export interface VerificationOptions {
  publicKey: Uint8Array
  currentSessionId: string
  /** If omitted, current Date.now() is used. */
  now?: number
  /**
   * Local verifier revocation state. A token is rejected when its token_id is
   * present in a set or the callback returns true. Callback implementations
   * should remain local; verification never performs a network lookup.
   */
  revokedTokenIds?: RevocationState
  /**
   * Optional authenticated presenter check. Since the presenter is not a
   * field in the wire token, the authenticated value is the final hop's
   * signed agent_id.
   */
  expectedPresenterAgentId?: string
  /**
   * Optional PoH verifier callback (spec Section 7.3 optional step).
   * If provided and the token has principal.poh_credential, this is called to
   * verify it. Returns true if credential is valid, false otherwise.
   */
  pohVerifier?: (credential: string) => Promise<boolean> | boolean
}

export interface VerificationResult {
  valid: boolean
  error?: HdpError
}

export type RecordIntegrityStatus = 'valid' | 'invalid' | 'unverified'
export type AcceptanceStatus = 'accepted' | 'rejected' | 'not_evaluated'
export type HistoricalAcceptanceStatus = 'accepted' | 'rejected' | 'indeterminate'

export interface RecordIntegrityReport {
  status: RecordIntegrityStatus
  /** True/false when evaluated; undefined means the key/algorithm was unavailable. */
  valid?: boolean
  error?: HdpError
}

export interface AcceptanceReport {
  status: AcceptanceStatus
  valid?: boolean
  error?: HdpError
}

export interface HistoricalAcceptanceEvidence {
  /** Digest of the complete token, normally from computeTokenDigest(). */
  tokenDigest: string
  /** Session in which the verifier evaluated the token. */
  sessionId: string
  /** Identity of the verifier that made the decision. */
  verifierId: string
  /** Evaluation time in Unix milliseconds. */
  evaluatedAt: number
  /** The verifier's recorded decision. */
  decision: 'accepted' | 'rejected'
  /** Evidence must be authenticated/integrity-protected by the application. */
  authenticated: boolean
  /** Whether the token was revoked at this verifier and evaluation time. */
  revoked: boolean
  /** Whether the verifier's applicable policy accepted the request. */
  policyAccepted: boolean
  [key: string]: unknown
}

export interface HistoricalAuditOptions {
  /** Trusted archived key used for record-integrity verification. */
  publicKey?: Uint8Array
  /** Options for evaluating current live acceptance, if desired. */
  currentVerification?: VerificationOptions
  /**
   * Convenience fields for current live evaluation when a nested options
   * object is not desired.
   */
  currentSessionId?: string
  now?: number
  revokedTokenIds?: RevocationState
  expectedPresenterAgentId?: string
  pohVerifier?: (credential: string) => Promise<boolean> | boolean
  /** Authenticated verifier receipt or integrity-protected log evidence. */
  evidence?: HistoricalAcceptanceEvidence
  /**
   * Optional application verifier for an evidence record. Returning true
   * establishes that the supplied evidence is authenticated; returning false
   * leaves the historical result indeterminate.
   */
  verifyEvidence?: (
    evidence: HistoricalAcceptanceEvidence,
    token: HdpToken,
  ) => boolean | Promise<boolean>
}

export interface HistoricalAcceptanceReport {
  status: HistoricalAcceptanceStatus
  valid?: boolean
  reason?: string
}

export interface HistoricalAuditReport {
  /** Signature/format result, independent from lifecycle and revocation. */
  recordIntegrity: RecordIntegrityReport
  /** Live acceptance, intentionally separate from historical evidence. */
  currentAcceptance: AcceptanceReport
  /** Acceptance established by authenticated evidence at a past time. */
  historicalAcceptance: HistoricalAcceptanceReport
}

const SUPPORTED_VERSIONS = new Set(['0.1'])
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER

type UnknownRecord = Record<string, unknown>

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function versionErrorFor(token: unknown): HdpError | undefined {
  if (!isRecord(token)) return undefined

  const hdp = token.hdp
  if (typeof hdp === 'string' && !SUPPORTED_VERSIONS.has(hdp)) {
    return new HdpUnsupportedVersionError(hdp)
  }

  const header = token.header
  if (isRecord(header) && 'version' in header && hdp !== undefined && header.version !== hdp) {
    return new HdpVersionMismatchError(hdp, header.version)
  }

  return undefined
}

function schemaError(detail: string): HdpSchemaError {
  return new HdpSchemaError(detail)
}

function checkSafeInteger(
  value: unknown,
  field: string,
  minimum: number,
): HdpSchemaError | undefined {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > MAX_SAFE_INTEGER) {
    return schemaError(`${field} must be an integer in the range ${minimum} through ${MAX_SAFE_INTEGER}`)
  }
  return undefined
}

/**
 * Validate the runtime input before any property is used by verification.
 * validateToken owns the JSON-schema checks; the additional checks here cover
 * the representation bounds and relationships required by draft -02.
 */
function validateVerifierInput(input: unknown): { token?: HdpToken; error?: HdpError } {
  const versionError = versionErrorFor(input)
  if (versionError) return { error: versionError }

  try {
    validateToken(input)
  } catch (error) {
    if (error instanceof HdpError) return { error }
    return { error: schemaError(error instanceof Error ? error.message : String(error)) }
  }

  if (!isRecord(input)) return { error: schemaError('token must be a JSON object') }

  // The schema fixes hdp to the only version currently supported. Keep this
  // explicit because the verifier's API accepts runtime values from JSON.
  if (input.hdp !== '0.1') return { error: new HdpUnsupportedVersionError(input.hdp) }

  const header = input.header
  if (!isRecord(header)) return { error: schemaError('header must be an object') }
  if (header.version !== input.hdp) {
    return { error: new HdpVersionMismatchError(input.hdp, header.version) }
  }

  const issuedError = checkSafeInteger(header.issued_at, 'header.issued_at', 0)
  if (issuedError) return { error: issuedError }
  const expiresError = checkSafeInteger(header.expires_at, 'header.expires_at', 0)
  if (expiresError) return { error: expiresError }

  const signature = input.signature
  if (!isRecord(signature)) return { error: schemaError('signature must be an object') }
  if (typeof signature.kid !== 'string' || typeof signature.value !== 'string') {
    return { error: schemaError('signature.kid and signature.value must be strings') }
  }

  const chain = input.chain
  if (!Array.isArray(chain)) return { error: schemaError('chain must be an array') }

  const scope = input.scope
  if (!isRecord(scope)) return { error: schemaError('scope must be an object') }
  if (scope.max_hops !== undefined) {
    const maxHopsError = checkSafeInteger(scope.max_hops, 'scope.max_hops', 1)
    if (maxHopsError) return { error: maxHopsError }
  }

  for (let i = 0; i < chain.length; i++) {
    const hop = chain[i]
    if (!isRecord(hop)) return { error: schemaError(`chain[${i}] must be an object`) }
    const seqError = checkSafeInteger(hop.seq, `chain[${i}].seq`, 1)
    if (seqError) return { error: seqError }
    const timestampError = checkSafeInteger(hop.timestamp, `chain[${i}].timestamp`, 0)
    if (timestampError) return { error: timestampError }
    const parentError = checkSafeInteger(hop.parent_hop, `chain[${i}].parent_hop`, 0)
    if (parentError) return { error: parentError }
    if (typeof hop.hop_signature !== 'string' || hop.hop_signature.length === 0) {
      return { error: schemaError(`chain[${i}].hop_signature must be a non-empty string`) }
    }
  }

  return { token: input as unknown as HdpToken }
}

function validateChainStructure(token: HdpToken): HdpError | undefined {
  const chain = token.chain
  let previousTimestamp: number | undefined

  for (let i = 0; i < chain.length; i++) {
    const hop = chain[i]
    if (hop.seq !== i + 1) {
      return new HdpChainIntegrityError(`seq gap at position ${i}: expected ${i + 1}, got ${hop.seq}`)
    }

    // parent_hop is either the root authorization (0), or the seq of any
    // already-recorded hop. A self/future reference is never valid.
    if (hop.parent_hop !== 0 && hop.parent_hop > i) {
      return new HdpChainIntegrityError(
        `hop ${hop.seq} has invalid parent_hop ${hop.parent_hop}; expected 0 or a prior hop`,
      )
    }

    if (previousTimestamp !== undefined && hop.timestamp < previousTimestamp) {
      return new HdpChainIntegrityError(
        `hop ${hop.seq} timestamp ${hop.timestamp} precedes predecessor timestamp ${previousTimestamp}`,
      )
    }
    previousTimestamp = hop.timestamp
  }

  return undefined
}

function maxHopsError(token: HdpToken): HdpError | undefined {
  if (token.scope.max_hops !== undefined && token.chain.length > token.scope.max_hops) {
    return new HdpMaxHopsExceededError(token.scope.max_hops)
  }
  return undefined
}

async function verifyRootSignature(token: HdpToken, publicKey: Uint8Array): Promise<HdpError | undefined> {
  if (token.signature.alg !== 'Ed25519') {
    return new HdpSignatureInvalidError(`unsupported signature algorithm: ${String(token.signature.alg)}`)
  }

  const rootValid = await verifyRoot(token as unknown as Record<string, unknown>, token.signature, publicKey)
  if (!rootValid) {
    return new HdpSignatureInvalidError('root signature verification failed')
  }

  return undefined
}

async function verifyHopSignatures(token: HdpToken, publicKey: Uint8Array): Promise<HdpError | undefined> {
  const chain = token.chain
  for (let i = 0; i < chain.length; i++) {
    const hop = chain[i]
    // Reconstruct what was signed: cumulative chain up to this hop, but
    // WITHOUT hop_signature on the current hop.
    const { hop_signature: currentHopSig, ...unsignedCurrentHop } = hop
    const cumulative = [...chain.slice(0, i), unsignedCurrentHop] as HopRecord[]
    const hopValid = await verifyHop(cumulative, token.signature.value, currentHopSig, publicKey)
    if (!hopValid) {
      return new HdpSignatureInvalidError(`hop ${hop.seq} signature verification failed`)
    }
  }

  return undefined
}

function selectRevocationState(opts: VerificationOptions): RevocationState | undefined {
  return opts.revokedTokenIds
}

async function isTokenRevoked(tokenId: string, state: RevocationState): Promise<boolean> {
  if (typeof state === 'function') return Boolean(await state(tokenId))
  return state.has(tokenId)
}

function expectedPresenter(opts: VerificationOptions): string | undefined {
  return opts.expectedPresenterAgentId
}

function presenterError(token: HdpToken, opts: VerificationOptions): HdpError | undefined {
  const expected = expectedPresenter(opts)
  if (expected === undefined) return undefined

  const actual = token.chain.length > 0 ? token.chain[token.chain.length - 1].agent_id : undefined
  if (actual !== expected) return new HdpPresenterMismatchError(expected, actual)
  return undefined
}

/**
 * Verify a token for live use. Expiry, revocation, session, and presenter
 * checks are intentionally not folded into the historical audit result.
 */
export async function verifyToken(
  token: HdpToken,
  opts: VerificationOptions,
): Promise<VerificationResult> {
  const now = opts.now ?? Date.now()
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    return { valid: false, error: schemaError('verification now must be a finite number') }
  }

  const prepared = validateVerifierInput(token)
  if (prepared.error || !prepared.token) {
    return { valid: false, error: prepared.error }
  }
  const verifiedToken = prepared.token

  // Lifecycle is an inclusive lower bound and strict upper bound.
  if (now < verifiedToken.header.issued_at) {
    return { valid: false, error: new HdpTokenNotYetValidError(verifiedToken.header.issued_at) }
  }
  if (now >= verifiedToken.header.expires_at) {
    return { valid: false, error: new HdpTokenExpiredError(verifiedToken.header.expires_at) }
  }

  const revocationState = selectRevocationState(opts)
  if (revocationState !== undefined) {
    try {
      if (await isTokenRevoked(verifiedToken.header.token_id, revocationState)) {
        return { valid: false, error: new HdpTokenRevokedError(verifiedToken.header.token_id) }
      }
    } catch (error) {
      // A failed local lookup is not evidence that a token is safe to use.
      const detail = error instanceof Error ? error.message : String(error)
      return { valid: false, error: new HdpSignatureInvalidError(`revocation check failed: ${detail}`) }
    }
  }

  const rootError = await verifyRootSignature(verifiedToken, opts.publicKey)
  if (rootError) return { valid: false, error: rootError }

  const chainError = validateChainStructure(verifiedToken)
  if (chainError) return { valid: false, error: chainError }

  const hopError = await verifyHopSignatures(verifiedToken, opts.publicKey)
  if (hopError) return { valid: false, error: hopError }

  const maxHops = maxHopsError(verifiedToken)
  if (maxHops) return { valid: false, error: maxHops }

  if (verifiedToken.header.session_id !== opts.currentSessionId) {
    return { valid: false, error: new HdpSessionMismatchError() }
  }

  const presenterMismatch = presenterError(verifiedToken, opts)
  if (presenterMismatch) return { valid: false, error: presenterMismatch }

  if (verifiedToken.principal.poh_credential && opts.pohVerifier) {
    const pohValid = await opts.pohVerifier(verifiedToken.principal.poh_credential)
    if (!pohValid) {
      return { valid: false, error: new HdpSignatureInvalidError('PoH credential verification failed') }
    }
  }

  return { valid: true }
}

/**
 * Compute the digest used to bind application-layer historical evidence to a
 * complete token record. The representation follows HDP's content-addressed
 * reference form (`sha256:` + unpadded base64url), without altering the token
 * or its wire format.
 */
export function computeTokenDigest(token: HdpToken): string {
  return contentAddressedReference(token)
}

function integrityReportError(error: HdpError): RecordIntegrityReport {
  return { status: 'invalid', valid: false, error }
}

async function verifyRecordIntegrity(
  input: HdpToken,
  publicKey: Uint8Array | undefined,
): Promise<RecordIntegrityReport> {
  const prepared = validateVerifierInput(input)
  if (prepared.error || !prepared.token) {
    return integrityReportError(prepared.error ?? schemaError('token could not be validated'))
  }
  const token = prepared.token

  if (token.header.expires_at <= token.header.issued_at) {
    return integrityReportError(schemaError('header.expires_at must be greater than header.issued_at'))
  }

  if (!publicKey) {
    const chainError = validateChainStructure(token)
    if (chainError) return integrityReportError(chainError)
    const maxHops = maxHopsError(token)
    if (maxHops) return integrityReportError(maxHops)
    return { status: 'unverified' }
  }

  const rootError = await verifyRootSignature(token, publicKey)
  if (rootError) return integrityReportError(rootError)

  const chainError = validateChainStructure(token)
  if (chainError) return integrityReportError(chainError)

  const hopError = await verifyHopSignatures(token, publicKey)
  if (hopError) return integrityReportError(hopError)

  const maxHops = maxHopsError(token)
  if (maxHops) return integrityReportError(maxHops)
  return { status: 'valid', valid: true }
}

function currentVerificationOptions(
  opts: HistoricalAuditOptions,
): VerificationOptions | undefined {
  const nested = opts.currentVerification
  if (nested) return nested
  if (!opts.publicKey || typeof opts.currentSessionId !== 'string') return undefined

  return {
    publicKey: opts.publicKey,
    currentSessionId: opts.currentSessionId,
    now: opts.now,
    revokedTokenIds: opts.revokedTokenIds,
    expectedPresenterAgentId: opts.expectedPresenterAgentId,
    pohVerifier: opts.pohVerifier,
  }
}

async function evaluateHistoricalAcceptance(
  token: HdpToken,
  integrity: RecordIntegrityReport,
  opts: HistoricalAuditOptions,
): Promise<HistoricalAcceptanceReport> {
  const evidence = opts.evidence
  if (!evidence) {
    return { status: 'indeterminate', reason: 'no historical acceptance evidence supplied' }
  }
  if (integrity.status !== 'valid') {
    return {
      status: 'indeterminate',
      reason: integrity.status === 'unverified'
        ? 'record integrity is unverified'
        : 'record integrity is invalid',
    }
  }

  let authenticated = evidence.authenticated === true
  const evidenceVerifier = opts.verifyEvidence
  if (evidenceVerifier) {
    try {
      authenticated = await evidenceVerifier(evidence, token)
    } catch {
      authenticated = false
    }
  }
  if (!authenticated) {
    return { status: 'indeterminate', reason: 'historical evidence is not authenticated' }
  }

  const suppliedDigest = evidence.tokenDigest
  if (typeof suppliedDigest !== 'string' || suppliedDigest.length === 0) {
    return { status: 'indeterminate', reason: 'historical evidence has no token digest' }
  }
  const digest = computeTokenDigest(token)
  if (suppliedDigest !== digest) {
    return { status: 'indeterminate', reason: 'historical evidence is bound to a different token' }
  }

  const sessionId = evidence.sessionId
  if (typeof sessionId !== 'string' || sessionId !== token.header.session_id) {
    return { status: 'indeterminate', reason: 'historical evidence session does not match the token' }
  }

  const verifierId = evidence.verifierId
  if (typeof verifierId !== 'string' || verifierId.length === 0) {
    return { status: 'indeterminate', reason: 'historical evidence identifies no verifier' }
  }

  const evaluatedAt = evidence.evaluatedAt
  if (
    typeof evaluatedAt !== 'number' ||
    !Number.isSafeInteger(evaluatedAt) ||
    evaluatedAt < token.header.issued_at ||
    evaluatedAt >= token.header.expires_at
  ) {
    return { status: 'indeterminate', reason: 'historical evaluation time is outside the token lifetime' }
  }

  const decision = evidence.decision
  if (decision === 'rejected') {
    return { status: 'rejected', valid: false }
  }

  if (evidence.revoked) {
    return { status: 'rejected', valid: false, reason: 'evidence records the token as revoked' }
  }
  if (evidence.policyAccepted !== true) {
    return { status: 'indeterminate', reason: 'historical policy acceptance is missing' }
  }

  return { status: 'accepted', valid: true }
}

/**
 * Produce an audit report without turning an expired or revoked token into a
 * new live authorization. Record integrity, current acceptance, and historical
 * acceptance are evaluated and reported independently.
 */
export async function auditToken(
  token: HdpToken,
  opts: HistoricalAuditOptions = {},
): Promise<HistoricalAuditReport> {
  const recordIntegrity = await verifyRecordIntegrity(token, opts.publicKey)

  let currentAcceptance: AcceptanceReport = {
    status: 'not_evaluated',
  }
  const currentOpts = currentVerificationOptions(opts)
  if (currentOpts) {
    const result = await verifyToken(token, currentOpts)
    currentAcceptance = result.valid
      ? { status: 'accepted', valid: true }
      : { status: 'rejected', valid: false, error: result.error }
  }

  const historicalAcceptance = await evaluateHistoricalAcceptance(token, recordIntegrity, opts)
  return { recordIntegrity, currentAcceptance, historicalAcceptance }
}
