// packages/hdp-physical/src/edt/signer.ts
import * as ed from '@noble/ed25519'
import type { EdtToken, SignedEdt } from '../types/edt.js'

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

export function canonicalizeEdt(edt: EdtToken): string {
  // RFC-8785 canonical JSON: sort keys recursively, no extra whitespace
  return JSON.stringify(sortKeysDeep(edt))
}

export async function signEdt(
  edt: EdtToken,
  privateKey: Uint8Array,
  kid: string
): Promise<SignedEdt> {
  const canonical = canonicalizeEdt(edt)
  const msgBytes = new TextEncoder().encode(canonical)
  const sigBytes = await ed.signAsync(msgBytes, privateKey)
  return {
    edt,
    signature: Buffer.from(sigBytes).toString('base64url'),
    kid,
    alg: 'Ed25519',
  }
}
