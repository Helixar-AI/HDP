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
}
