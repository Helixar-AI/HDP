import { createHash } from 'node:crypto'
import { canonicalizeFields } from '../crypto/canonical.js'
import { validateToken } from '../schema/validator.js'
import type { HdpToken } from '../types/token.js'

/**
 * Errors raised when a token reference cannot be resolved without violating
 * the integrity requirements of the token-by-reference transport.
 */
export class TokenReferenceIntegrityError extends Error {
  readonly code = 'TOKEN_REFERENCE_INTEGRITY'

  constructor(detail: string) {
    super(`TOKEN_REFERENCE_INTEGRITY: ${detail}`)
    this.name = 'TokenReferenceIntegrityError'
  }
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const SHA256_PREFIX = 'sha256:'
const SHA256_DIGEST_LENGTH = 32

/** Reject values that an object-to-JSON conversion would silently coerce. */
function assertJsonRepresentation(value: unknown, path: string, ancestors: Set<object>): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TokenReferenceIntegrityError(`${path} is not a finite JSON number`)
    }
    return
  }
  if (value === undefined) {
    throw new TokenReferenceIntegrityError(`${path} is undefined`)
  }
  if (typeof value !== 'object') {
    throw new TokenReferenceIntegrityError(`${path} is not a JSON value`)
  }

  if (ancestors.has(value)) throw new TokenReferenceIntegrityError(`${path} contains a cyclic object`)
  ancestors.add(value)
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        assertJsonRepresentation(value[i], `${path}[${i}]`, ancestors)
      }
      return
    }

    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TokenReferenceIntegrityError(`${path} is not a JSON object`)
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TokenReferenceIntegrityError(`${path} contains symbol properties`)
    }
    for (const key of Object.keys(value)) {
      assertJsonRepresentation((value as Record<string, unknown>)[key], `${path}.${key}`, ancestors)
    }
  } finally {
    ancestors.delete(value)
  }
}

/**
 * Perform the representation and schema checks required before a token is
 * used as a reference target.
 */
export function assertTokenRepresentation(value: unknown): asserts value is HdpToken {
  assertJsonRepresentation(value, '$', new Set<object>())
  try {
    validateToken(value)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new TokenReferenceIntegrityError(`resolved token failed schema validation: ${detail}`)
  }
}

/** Return the RFC 8785 canonical JSON representation of a complete token. */
export function canonicalToken(token: HdpToken): string {
  assertTokenRepresentation(token)
  try {
    return canonicalizeFields(token as unknown as Record<string, unknown>)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new TokenReferenceIntegrityError(`token cannot be canonicalized: ${detail}`)
  }
}

/**
 * Make a detached immutable snapshot.  Parsing the canonical form both
 * removes caller-owned object references and guarantees that all aliases in
 * a store compare the same way.
 */
export function snapshotToken(token: HdpToken): HdpToken {
  const canonical = canonicalToken(token)
  try {
    return JSON.parse(canonical) as HdpToken
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new TokenReferenceIntegrityError(`token snapshot cannot be decoded: ${detail}`)
  }
}

/** Compute `sha256:<unpadded-base64url(SHA-256(canonical-token))>`. */
export function contentAddressedReference(token: HdpToken): string {
  const canonical = canonicalToken(token)
  const digest = createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('base64url')
  return `${SHA256_PREFIX}${digest}`
}

/** Backwards-friendly aliases for callers that prefer a shorter name. */
export const tokenContentReference = contentAddressedReference
export const tokenReference = contentAddressedReference

export function isUuidReference(reference: string): boolean {
  return UUID_PATTERN.test(reference)
}

export function normalizeUuid(reference: string): string {
  return reference.toLowerCase()
}

/** Store UUID references by their canonical textual spelling. */
export function normalizeStoreKey(reference: string): string {
  return isUuidReference(reference) ? normalizeUuid(reference) : reference
}

/**
 * Validate and return the digest portion of a content-addressed reference.
 * Buffer's base64 decoder is intentionally permissive, so the regular
 * expression and round-trip check are both required to enforce canonical,
 * unpadded base64url.
 */
export function parseContentAddressedReference(reference: string): string {
  if (!reference.startsWith(SHA256_PREFIX)) {
    throw new TokenReferenceIntegrityError('invalid content-addressed reference prefix')
  }

  const encodedDigest = reference.slice(SHA256_PREFIX.length)
  if (!/^[A-Za-z0-9_-]{43}$/.test(encodedDigest)) {
    throw new TokenReferenceIntegrityError('SHA-256 reference digest must be 32-byte unpadded base64url')
  }

  const digestBytes = Buffer.from(encodedDigest, 'base64url')
  if (digestBytes.length !== SHA256_DIGEST_LENGTH
    || digestBytes.toString('base64url') !== encodedDigest) {
    throw new TokenReferenceIntegrityError('SHA-256 reference digest is not canonical')
  }

  return encodedDigest
}

export function isContentAddressedReference(reference: string): boolean {
  return reference.startsWith(SHA256_PREFIX)
}

export function canonicalTokensEqual(left: HdpToken, right: HdpToken): boolean {
  return canonicalToken(left) === canonicalToken(right)
}
