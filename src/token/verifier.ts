import { verifyRoot, verifyHop } from '../crypto/verify.js'
import { validateToken } from '../schema/validator.js'
import { contentAddressedReference } from '../transport/token-reference.js'
import type { HopRecord } from '../types/chain.js'
import type { HdpToken } from '../types/token.js'
import {
  HdpChainIntegrityError,
  HdpError,
  HdpMaxHopsExceededError,
  HdpSchemaError,
  HdpSignatureInvalidError,
  HdpUnsupportedVersionError,
  HdpVersionMismatchError,
} from '../types/errors.js'

export type IntegrityStep = 0 | 1 | 2 | 3 | 4 | 5

export interface VerificationOptions {
  publicKey: Uint8Array
}

export type VerificationResult =
  | { valid: true }
  | { valid: false; failedStep: IntegrityStep; error: HdpError }

export interface AuditOptions {
  publicKey?: Uint8Array
  sessionId?: string
  linkedRecordRelationship?: 'supersession' | 'joint_approval'
  pohVerifier?: (credential: string, token: HdpToken) => boolean | Promise<boolean>
}

export interface AuditReport {
  integrity:
    | { status: 'valid' }
    | { status: 'invalid'; failedStep: IntegrityStep; error: HdpError }
    | { status: 'unverified' }
  recordingPeriod:
    | { status: 'within_period' }
    | { status: 'recorded_after_period'; hopSeqs: number[] }
    | { status: 'not_checked' }
  session: { status: 'match' | 'mismatch' | 'not_checked' }
  linkedRecords:
    | { status: 'none' }
    | { status: 'linked'; parentTokenId: string; relationship: 'supersession' | 'joint_approval' | 'unknown' }
    | { status: 'not_checked' }
  poh: { status: 'verified' | 'failed' | 'not_checked' }
}

const SUPPORTED_VERSIONS = new Set(['0.1'])
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER

type UnknownRecord = Record<string, unknown>

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function schemaError(detail: string): HdpSchemaError {
  return new HdpSchemaError(detail)
}

function versionErrorFor(token: HdpToken): HdpError | undefined {
  if (!SUPPORTED_VERSIONS.has(token.hdp)) {
    return new HdpUnsupportedVersionError(token.hdp)
  }
  if (token.header.version !== token.hdp) {
    return new HdpVersionMismatchError(token.hdp, token.header.version)
  }
  return undefined
}

function validateVerifierInput(input: unknown): { token?: HdpToken; error?: HdpError } {
  try {
    validateToken(input)
  } catch (error) {
    if (error instanceof HdpError) return { error }
    return { error: schemaError(error instanceof Error ? error.message : String(error)) }
  }

  if (!isRecord(input)) return { error: schemaError('token must be a JSON object') }

  const header = input.header
  if (!isRecord(header)) return { error: schemaError('header must be an object') }

  const signature = input.signature
  if (!isRecord(signature)) return { error: schemaError('signature must be an object') }
  if (typeof signature.kid !== 'string' || typeof signature.value !== 'string') {
    return { error: schemaError('signature.kid and signature.value must be strings') }
  }

  const chain = input.chain
  if (!Array.isArray(chain)) return { error: schemaError('chain must be an array') }
  const scope = input.scope
  if (!isRecord(scope)) return { error: schemaError('scope must be an object') }

  return { token: input as unknown as HdpToken }
}

function validateChainStructure(token: HdpToken): HdpError | undefined {
  const priorSequences = new Set<number>()
  let previousTimestamp: number | undefined

  for (let i = 0; i < token.chain.length; i++) {
    const hop = token.chain[i]
    const expectedSeq = i + 1
    if (hop.seq !== expectedSeq) {
      return new HdpChainIntegrityError(`seq gap at position ${i}: expected ${expectedSeq}, got ${hop.seq}`)
    }

    if (hop.parent_hop !== 0 && !priorSequences.has(hop.parent_hop)) {
      return new HdpChainIntegrityError(
        `hop ${hop.seq} has invalid parent_hop ${hop.parent_hop}; expected 0 or a prior hop`,
      )
    }

    if (previousTimestamp !== undefined && hop.timestamp < previousTimestamp) {
      return new HdpChainIntegrityError(
        `hop ${hop.seq} timestamp ${hop.timestamp} precedes predecessor timestamp ${previousTimestamp}`,
      )
    }

    priorSequences.add(hop.seq)
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
  if (!rootValid) return new HdpSignatureInvalidError('root signature verification failed')
  return undefined
}

async function verifyHopSignatures(token: HdpToken, publicKey: Uint8Array): Promise<HdpError | undefined> {
  for (let i = 0; i < token.chain.length; i++) {
    const hop = token.chain[i]
    const { hop_signature: currentHopSig, ...unsignedCurrentHop } = hop
    const cumulative = [...token.chain.slice(0, i), unsignedCurrentHop] as HopRecord[]
    if (typeof currentHopSig !== 'string' || currentHopSig.length === 0) {
      return new HdpSignatureInvalidError(`hop ${hop.seq} signature is missing`)
    }
    const hopValid = await verifyHop(cumulative, token.signature.value, currentHopSig, publicKey)
    if (!hopValid) return new HdpSignatureInvalidError(`hop ${hop.seq} signature verification failed`)
  }
  return undefined
}

/**
 * Verify record integrity in the six ordered draft -03 steps. The result uses
 * only the token and issuer public key, so it is independent of time and session.
 */
export async function verifyToken(
  token: unknown,
  opts: VerificationOptions,
): Promise<VerificationResult> {
  const prepared = validateVerifierInput(token)
  if (prepared.error || !prepared.token) {
    return { valid: false, failedStep: 0, error: prepared.error ?? schemaError('token could not be validated') }
  }

  const verifiedToken = prepared.token
  const versionError = versionErrorFor(verifiedToken)
  if (versionError) return { valid: false, failedStep: 1, error: versionError }

  const rootError = await verifyRootSignature(verifiedToken, opts.publicKey)
  if (rootError) return { valid: false, failedStep: 2, error: rootError }

  const chainError = validateChainStructure(verifiedToken)
  if (chainError) return { valid: false, failedStep: 3, error: chainError }

  const hopError = await verifyHopSignatures(verifiedToken, opts.publicKey)
  if (hopError) return { valid: false, failedStep: 4, error: hopError }

  const recordedDepthError = maxHopsError(verifiedToken)
  if (recordedDepthError) return { valid: false, failedStep: 5, error: recordedDepthError }

  return { valid: true }
}

/** Compute the canonical digest reference for a complete token record. */
export function computeTokenDigest(token: HdpToken): string {
  return contentAddressedReference(token)
}

/** Report record integrity and related audit findings without access decisions. */
export async function auditToken(
  token: unknown,
  opts: AuditOptions = {},
): Promise<AuditReport> {
  const prepared = validateVerifierInput(token)
  if (prepared.error || !prepared.token) {
    return {
      integrity: {
        status: 'invalid',
        failedStep: 0,
        error: prepared.error ?? schemaError('token could not be validated'),
      },
      recordingPeriod: { status: 'not_checked' },
      session: { status: 'not_checked' },
      linkedRecords: { status: 'not_checked' },
      poh: { status: 'not_checked' },
    }
  }

  const validatedToken = prepared.token
  let integrity: AuditReport['integrity']
  if (!opts.publicKey) {
    integrity = { status: 'unverified' }
  } else {
    const verification = await verifyToken(validatedToken, { publicKey: opts.publicKey })
    integrity = verification.valid
      ? { status: 'valid' }
      : { status: 'invalid', failedStep: verification.failedStep, error: verification.error }
  }

  const hopSeqs = validatedToken.chain
    .filter(hop => hop.timestamp >= validatedToken.header.expires_at)
    .map(hop => hop.seq)
  const recordingPeriod: AuditReport['recordingPeriod'] = hopSeqs.length > 0
    ? { status: 'recorded_after_period', hopSeqs }
    : { status: 'within_period' }

  const session: AuditReport['session'] = opts.sessionId === undefined
    ? { status: 'not_checked' }
    : { status: validatedToken.header.session_id === opts.sessionId ? 'match' : 'mismatch' }

  const parentTokenId = validatedToken.header.parent_token_id
  const linkedRecords: AuditReport['linkedRecords'] = parentTokenId === undefined
    ? { status: 'none' }
    : {
        status: 'linked',
        parentTokenId,
        relationship: opts.linkedRecordRelationship ?? 'unknown',
      }

  let poh: AuditReport['poh'] = { status: 'not_checked' }
  const credential = validatedToken.principal.poh_credential
  if (credential !== undefined && opts.pohVerifier) {
    try {
      poh = await opts.pohVerifier(credential, validatedToken)
        ? { status: 'verified' }
        : { status: 'failed' }
    } catch {
      poh = { status: 'failed' }
    }
  }

  return { integrity, recordingPeriod, session, linkedRecords, poh }
}
