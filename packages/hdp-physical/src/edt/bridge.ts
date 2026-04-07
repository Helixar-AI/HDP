// packages/hdp-physical/src/edt/bridge.ts
import type { SignedEdt } from '../types/edt.js'

/**
 * Converts a SignedEdt into a plain object suitable for HdpScope.extensions['hdp-p'].
 * This embeds the EDT into a standard HDP token without changing the core schema.
 */
export function edtToHdpExtension(signed: SignedEdt): Record<string, unknown> {
  return {
    'hdp-p': {
      edt: signed.edt,
      signature: signed.signature,
      kid: signed.kid,
      alg: signed.alg,
    },
  }
}

/**
 * Extracts a SignedEdt from HdpScope.extensions, returning null if not present or malformed.
 */
export function edtFromHdpExtension(
  extensions: Record<string, unknown> | undefined
): SignedEdt | null {
  const raw = extensions?.['hdp-p']
  if (!raw || typeof raw !== 'object') return null
  const p = raw as Record<string, unknown>
  if (!p.edt || !p.signature || !p.kid || p.alg !== 'Ed25519') return null
  return p as unknown as SignedEdt
}
