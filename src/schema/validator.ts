// The token schema validator is compiled at build time by
// scripts/build-validator.mjs (Ajv standalone code), not at load time. Compiling
// at load time needs runtime code generation, which Cloudflare Workers and
// strict Content-Security-Policy environments refuse, so the package would fail
// to load there.
import { validate, type ValidationError } from './validator.generated.js'
import { HdpSchemaError } from '../types/errors.js'

// Reproduces Ajv's default errorsText() output ("data<path> <message>", joined
// with ", "), so error messages are unchanged from the runtime-compiled
// validator.
function formatErrors(errors: ValidationError[] | null | undefined): string {
  if (!errors || errors.length === 0) return 'No errors'
  return errors.map((e) => `data${e.instancePath} ${e.message}`).join(', ')
}

export function validateToken(token: unknown): void {
  const valid = validate(token)
  if (!valid) {
    throw new HdpSchemaError(formatErrors(validate.errors))
  }

  const candidate = token as { header: { issued_at: number; expires_at: number } }
  if (candidate.header.expires_at <= candidate.header.issued_at) {
    throw new HdpSchemaError('header.expires_at must be greater than header.issued_at')
  }

  assertValidUnicode(token)
}

function assertValidUnicode(value: unknown): void {
  if (typeof value === 'string') {
    for (let i = 0; i < value.length; i++) {
      const unit = value.charCodeAt(i)
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(i + 1)
        if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) {
          throw new HdpSchemaError('token contains an invalid Unicode string')
        }
        i++
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw new HdpSchemaError('token contains an invalid Unicode string')
      }
    }
    return
  }

  if (Array.isArray(value)) {
    for (const item of value) assertValidUnicode(item)
    return
  }

  if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      assertValidUnicode(key)
      assertValidUnicode(item)
    }
  }
}
