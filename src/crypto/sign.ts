import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import { canonicalizeFields } from './canonical.js'
import { validateToken } from '../schema/validator.js'
import { HdpSchemaError } from '../types/errors.js'
import type { HdpSignature, UnsignedToken } from '../types/token.js'
import type { HopRecord } from '../types/chain.js'

// @noble/ed25519 v3 requires setting the hash for sync methods
ed.hashes.sha512 = sha512

export async function signRoot(
  token: UnsignedToken,
  privateKey: Uint8Array,
  kid: string
): Promise<HdpSignature> {
  const candidate = {
    ...token,
    signature: { alg: 'Ed25519', kid, value: 'A'.repeat(86) },
  }
  validateToken(candidate)
  if (token.chain.length !== 0) {
    throw new HdpSchemaError('root signing requires an empty issuance-time chain')
  }

  const payload: UnsignedToken = {
    hdp: token.hdp,
    header: token.header,
    principal: token.principal,
    scope: token.scope,
    chain: [],
  }
  const canonical = canonicalizeFields(payload as any)
  const msgBytes = new TextEncoder().encode(canonical)
  const sigBytes = await ed.signAsync(msgBytes, privateKey)
  return {
    alg: 'Ed25519',
    kid,
    value: Buffer.from(sigBytes).toString('base64url'),
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
  const payload = [rootSigValue, ...cumulativeChain]
  const canonical = canonicalizeFields(payload as any)
  const msgBytes = new TextEncoder().encode(canonical)
  const sigBytes = await ed.signAsync(msgBytes, privateKey)
  return Buffer.from(sigBytes).toString('base64url')
}
