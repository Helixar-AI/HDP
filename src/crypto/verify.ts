import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import { canonicalizeFields } from './canonical.js'
import type { HdpSignature, UnsignedToken } from '../types/token.js'
import type { HopRecord } from '../types/chain.js'

// @noble/ed25519 v3 requires setting the hash for sync methods
ed.hashes.sha512 = sha512

export async function verifyRoot(
  token: Omit<UnsignedToken, 'chain'>,
  signature: HdpSignature,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const canonical = canonicalizeFields(token as any, ['header', 'principal', 'scope'])
    const msgBytes = new TextEncoder().encode(canonical)
    const sigBytes = Buffer.from(signature.value, 'base64url')
    return await ed.verifyAsync(sigBytes, msgBytes, publicKey)
  } catch {
    return false
  }
}

export async function verifyHop(
  cumulativeChain: HopRecord[],
  rootSigValue: string,
  hopSignature: string,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const payload = { chain: cumulativeChain, root_sig: rootSigValue }
    const canonical = canonicalizeFields(payload as any)
    const msgBytes = new TextEncoder().encode(canonical)
    const sigBytes = Buffer.from(hopSignature, 'base64url')
    return await ed.verifyAsync(sigBytes, msgBytes, publicKey)
  } catch {
    return false
  }
}
