import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import { canonicalizeFields } from './canonical.js'
import type { HdpSignature, UnsignedToken } from '../types/token.js'
import type { HopRecord } from '../types/chain.js'

// @noble/ed25519 v3 requires setting the hash for sync methods
ed.hashes.sha512 = sha512

const SIGNED_FIELDS = ['header', 'principal', 'scope'] as const

export async function signRoot(
  token: UnsignedToken,
  privateKey: Uint8Array,
  kid: string
): Promise<HdpSignature> {
  const canonical = canonicalizeFields(token as any, [...SIGNED_FIELDS])
  const msgBytes = new TextEncoder().encode(canonical)
  const sigBytes = await ed.signAsync(msgBytes, privateKey)
  return {
    alg: 'Ed25519',
    kid,
    value: Buffer.from(sigBytes).toString('base64url'),
    signed_fields: ['header', 'principal', 'scope'] as const,
  }
}

/**
 * Signs a hop record over the cumulative chain state (all hops seq <= current)
 * plus the root signature value, as required by spec Section 7.2.
 */
export async function signHop(
  cumulativeChain: HopRecord[],
  rootSigValue: string,
  privateKey: Uint8Array
): Promise<string> {
  const payload = { chain: cumulativeChain, root_sig: rootSigValue }
  const canonical = canonicalizeFields(payload as any)
  const msgBytes = new TextEncoder().encode(canonical)
  const sigBytes = await ed.signAsync(msgBytes, privateKey)
  return Buffer.from(sigBytes).toString('base64url')
}
