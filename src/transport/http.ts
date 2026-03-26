import type { HdpToken } from '../types/token.js'
import { HdpSchemaError } from '../types/errors.js'

export const HDP_HEADER = 'X-HDP-Token'
export const HDP_REF_HEADER = 'X-HDP-Token-Ref'

export function encodeHeader(token: HdpToken): string {
  const json = JSON.stringify(token)
  return Buffer.from(json, 'utf8').toString('base64url')
}

export function decodeHeader(value: string): HdpToken {
  try {
    const json = Buffer.from(value, 'base64url').toString('utf8')
    return JSON.parse(json) as HdpToken
  } catch (e) {
    throw new HdpSchemaError(`Failed to decode X-HDP-Token header: ${(e as Error).message}`)
  }
}
