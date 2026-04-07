// packages/hdp-physical/src/edt/verifier.ts
import * as ed from '@noble/ed25519'
import type { SignedEdt } from '../types/edt.js'

function sortKeysDeep(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeysDeep)
  if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, sortKeysDeep(v)])
    )
  }
  return obj
}

export async function verifyEdt(
  signed: SignedEdt,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const canonical = JSON.stringify(sortKeysDeep(signed.edt))
    const msgBytes = new TextEncoder().encode(canonical)
    const sigBytes = Buffer.from(signed.signature, 'base64url')
    return await ed.verifyAsync(sigBytes, msgBytes, publicKey)
  } catch {
    return false
  }
}
