import Ajv from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import schema from './token.schema.json'
import { HdpSchemaError } from '../types/errors.js'

const ajv = new Ajv({ strict: false })
addFormats(ajv)
const validate = ajv.compile(schema)

export function validateToken(token: unknown): void {
  const valid = validate(token)
  if (!valid) {
    const msg = ajv.errorsText(validate.errors)
    throw new HdpSchemaError(msg)
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
