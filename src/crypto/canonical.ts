import { canonicalize } from 'json-canonicalize'

/**
 * Serializes an object (or a subset of its fields) to canonical JSON (RFC 8785).
 * When `fields` is provided, only those keys are included in the output,
 * assembled in the order listed in `fields`.
 */
export function canonicalizeFields(obj: Record<string, unknown>, fields?: string[]): string {
  if (!fields) return canonicalize(obj)
  const subset: Record<string, unknown> = {}
  for (const f of fields) {
    if (f in obj) subset[f] = obj[f]
  }
  return canonicalize(subset)
}
