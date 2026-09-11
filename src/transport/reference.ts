import type { HdpToken } from '../types/token.js'
import type { TokenStore } from './store.js'
import {
  canonicalToken,
  contentAddressedReference,
  isContentAddressedReference,
  isUuidReference,
  normalizeStoreKey,
  normalizeUuid,
  parseContentAddressedReference,
  snapshotToken,
  TokenReferenceIntegrityError,
} from './token-reference.js'

/**
 * Store a token under its UUID token_id and its content address.  The UUID
 * write preserves the original API; callers extending a token with the same
 * token_id can pass the newly computed content reference as `reference` to
 * retain the previous UUID snapshot unchanged.
 */
export async function storeToken(
  store: TokenStore,
  token: HdpToken,
  reference?: string,
): Promise<string> {
  const snapshot = snapshotToken(token)
  const canonical = canonicalToken(snapshot)
  const contentReference = contentAddressedReference(snapshot)
  const references = reference === undefined
    ? [snapshot.header.token_id, contentReference]
    : [reference]

  if (reference !== undefined) {
    validateStorageReference(reference, snapshot, contentReference)
  }

  // Check every alias before writing any of them, so a conflicting UUID
  // reference cannot leave a partially-written content reference behind.
  const normalizedReferences = [...new Set(references.map(normalizeStoreKey))]
  for (const ref of normalizedReferences) {
    await assertWritable(store, ref, canonical)
  }

  for (const ref of normalizedReferences) {
    await store.put(ref, snapshot)
  }

  return reference ?? snapshot.header.token_id
}

/** Store only a content-addressed snapshot and return its immutable reference. */
export async function storeTokenByReference(store: TokenStore, token: HdpToken): Promise<string> {
  const reference = contentAddressedReference(token)
  await storeToken(store, token, reference)
  return reference
}

/** Resolve either a UUID token_id reference or a SHA-256 content reference. */
export async function resolveToken(store: TokenStore, reference: string): Promise<HdpToken | null> {
  if (typeof reference !== 'string' || reference.length === 0) {
    throw new TokenReferenceIntegrityError('token reference must be a non-empty string')
  }

  let token: HdpToken | null
  if (isContentAddressedReference(reference)) {
    // Parse before lookup so malformed references are rejected even when the
    // store has no entry for them.
    parseContentAddressedReference(reference)
    token = await readReference(store, reference)
  } else if (isUuidReference(reference)) {
    token = await readReference(store, reference)
  } else {
    throw new TokenReferenceIntegrityError(
      'token reference must be a version 4 UUID or sha256 content reference',
    )
  }

  if (token === null || token === undefined) return null

  const resolved = snapshotToken(token)
  if (isContentAddressedReference(reference)) {
    const actual = contentAddressedReference(resolved)
    if (actual !== reference) {
      throw new TokenReferenceIntegrityError(
        `content reference digest mismatch: expected '${reference}', got '${actual}'`,
      )
    }
  } else {
    const tokenId = resolved.header.token_id
    if (!isUuidReference(tokenId) || normalizeUuid(tokenId) !== normalizeUuid(reference)) {
      throw new TokenReferenceIntegrityError(
        `UUID reference '${reference}' resolved to token_id '${tokenId}'`,
      )
    }
  }

  return resolved
}

async function assertWritable(store: TokenStore, reference: string, canonical: string): Promise<void> {
  const existing = await readReference(store, reference)
  if (existing === null || existing === undefined) return

  const existingCanonical = canonicalToken(existing)
  if (existingCanonical !== canonical) {
    throw new TokenReferenceIntegrityError(`reference '${reference}' already identifies a different token`)
  }
}

/**
 * UUID lookups are case-insensitive by UUID value.  The first lookup uses the
 * normalized key used by InMemoryTokenStore; the fallback keeps custom stores
 * that retained a legacy upper-case spelling compatible.
 */
async function readReference(store: TokenStore, reference: string): Promise<HdpToken | null> {
  const normalized = normalizeStoreKey(reference)
  const resolved = await store.get(normalized)
  if (resolved !== null && resolved !== undefined) return resolved
  if (normalized !== reference) return store.get(reference)
  return null
}

function validateStorageReference(reference: string, token: HdpToken, expectedContentReference: string): void {
  if (isContentAddressedReference(reference)) {
    parseContentAddressedReference(reference)
    if (reference !== expectedContentReference) {
      throw new TokenReferenceIntegrityError(
        `content reference '${reference}' does not match the token digest '${expectedContentReference}'`,
      )
    }
    return
  }

  if (isUuidReference(reference)) {
    const tokenId = token.header.token_id
    if (!isUuidReference(tokenId) || normalizeUuid(tokenId) !== normalizeUuid(reference)) {
      throw new TokenReferenceIntegrityError(
        `UUID reference '${reference}' does not identify token_id '${tokenId}'`,
      )
    }
    return
  }

  throw new TokenReferenceIntegrityError(
    'storage reference must be a version 4 UUID or sha256 content reference',
  )
}

export {
  contentAddressedReference,
  TokenReferenceIntegrityError,
} from './token-reference.js'
