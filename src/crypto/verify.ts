import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import { canonicalizeFields } from './canonical.js'
import { validateToken } from '../schema/validator.js'
import type { HdpSignature, UnsignedToken } from '../types/token.js'
import type { HopRecord } from '../types/chain.js'

// @noble/ed25519 v3 requires setting the hash for sync methods
ed.hashes.sha512 = sha512

export async function verifyRoot(
  token: Record<string, unknown>,
  signature: HdpSignature,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    if (signature.alg !== 'Ed25519') return false
    validateToken({ ...token, signature })
    const payload: UnsignedToken = {
      hdp: token.hdp as UnsignedToken['hdp'],
      header: token.header as UnsignedToken['header'],
      principal: token.principal as UnsignedToken['principal'],
      scope: token.scope as UnsignedToken['scope'],
      chain: [],
    }
    const canonical = canonicalizeFields(payload as any)
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
    const payload = [rootSigValue, ...cumulativeChain]
    const canonical = canonicalizeFields(payload as any)
    const msgBytes = new TextEncoder().encode(canonical)
    const sigBytes = Buffer.from(hopSignature, 'base64url')
    return await ed.verifyAsync(sigBytes, msgBytes, publicKey)
  } catch {
    return false
  }
}
