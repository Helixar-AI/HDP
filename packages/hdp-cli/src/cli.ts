/**
 * hdp-validate — HDP token validator CLI
 *
 * Usage:
 *   hdp-validate <token.json>
 *   cat token.json | hdp-validate
 *   echo '{"hdp":"0.1",...}' | hdp-validate
 *
 * Exit codes:
 *   0 — token structure is schema-valid (note: signature cannot be verified without a public key)
 *   1 — token is invalid (schema violations, expiry, version, etc.)
 *   2 — usage error (bad arguments, unreadable file)
 */

import { readFileSync } from 'fs'
import { validateToken, HdpError } from '@helixar_ai/hdp'

function printUsage() {
  console.error('Usage: hdp-validate <token.json>')
  console.error('       cat token.json | hdp-validate')
  console.error('')
  console.error('Validates the schema and structure of an HDP token.')
  console.error('Note: cryptographic signature verification requires a public key.')
  console.error('      Use the @helixar_ai/hdp TypeScript library for full verification.')
}

function readInput(args: string[]): string {
  if (args.length === 0) {
    // Read from stdin
    return readFileSync('/dev/stdin', 'utf8')
  }
  if (args.length === 1) {
    const file = args[0]
    try {
      return readFileSync(file, 'utf8')
    } catch (e) {
      console.error(`Error: cannot read file '${file}': ${(e as Error).message}`)
      process.exit(2)
    }
  }
  printUsage()
  process.exit(2)
}

function validateStructure(token: unknown): string[] {
  const errors: string[] = []

  if (typeof token !== 'object' || token === null || Array.isArray(token)) {
    return ['TOKEN_STRUCTURE: root must be a JSON object']
  }

  const t = token as Record<string, unknown>

  // Version check
  if (t.hdp !== '0.1') {
    errors.push(`VERSION: unsupported hdp version '${t.hdp}' (expected '0.1')`)
  }

  // Expiry check (structural only — no time source required)
  if (typeof t.header === 'object' && t.header !== null) {
    const header = t.header as Record<string, unknown>
    if (typeof header.expires_at === 'number' && header.expires_at < Date.now()) {
      const expired = new Date(header.expires_at as number).toISOString()
      errors.push(`TOKEN_EXPIRED: token expired at ${expired}`)
    }
  }

  // Chain hop_signature presence
  if (Array.isArray(t.chain)) {
    for (const hop of t.chain as unknown[]) {
      if (typeof hop === 'object' && hop !== null) {
        const h = hop as Record<string, unknown>
        if (!h.hop_signature) {
          errors.push(`CHAIN_INTEGRITY: hop seq=${h.seq} is missing required hop_signature`)
        }
      }
    }
  }

  return errors
}

async function main() {
  const args = process.argv.slice(2)
  const raw = readInput(args)

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (e) {
    console.error(`✗ INVALID: not valid JSON — ${(e as Error).message}`)
    process.exit(1)
  }

  // Run schema validation
  try {
    validateToken(parsed)
  } catch (e) {
    const msg = e instanceof HdpError ? e.message : String(e)
    console.error(`✗ INVALID: ${msg}`)
    process.exit(1)
  }

  // Run structural checks (expiry, hop signatures, version)
  const structuralErrors = validateStructure(parsed)
  if (structuralErrors.length > 0) {
    for (const err of structuralErrors) {
      console.error(`✗ INVALID: ${err}`)
    }
    process.exit(1)
  }

  // Schema valid + structure OK
  const t = parsed as Record<string, unknown>
  const header = t.header as Record<string, unknown>
  const scope = t.scope as Record<string, unknown>
  const chain = t.chain as unknown[]

  console.log(`✓ VALID`)
  console.log(`  token_id:    ${header.token_id}`)
  console.log(`  session_id:  ${header.session_id}`)
  console.log(`  expires_at:  ${new Date(header.expires_at as number).toISOString()}`)
  console.log(`  intent:      ${scope.intent}`)
  console.log(`  chain hops:  ${chain.length}`)
  console.log(``)
  console.log(`  Note: cryptographic signature not verified (requires public key).`)
  console.log(`  Use @helixar_ai/hdp for full verification including Ed25519 signature check.`)

  process.exit(0)
}

main().catch(e => {
  console.error(`Unexpected error: ${e}`)
  process.exit(2)
})
