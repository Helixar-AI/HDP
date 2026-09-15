import type { HdpToken } from '../types/token.js'
import { HdpSchemaError } from '../types/errors.js'
import { validateToken } from '../schema/validator.js'

/** Standard HDP token header defined by draft -02. */
export const HDP_HEADER = 'HDP-Token'
/** Standard HDP token-reference header defined by draft -02. */
export const HDP_REF_HEADER = 'HDP-Token-Ref'

/**
 * @deprecated X-prefixed names are retained only for parsing legacy inbound
 * requests. New requests MUST use {@link HDP_HEADER}.
 */
export const HDP_LEGACY_HEADER = 'X-HDP-Token'
/**
 * @deprecated X-prefixed names are retained only for parsing legacy inbound
 * requests. New requests MUST use {@link HDP_REF_HEADER}.
 */
export const HDP_LEGACY_REF_HEADER = 'X-HDP-Token-Ref'

export function encodeHeader(token: HdpToken): string {
  const json = JSON.stringify(token)
  return Buffer.from(json, 'utf8').toString('base64url')
}

export function decodeHeader(value: string): HdpToken {
  try {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error('header value must use unpadded base64url')
    }

    const bytes = Buffer.from(value, 'base64url')
    if (bytes.toString('base64url') !== value) {
      throw new Error('header value is not canonical base64url')
    }

    const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    assertNoDuplicateObjectNames(json)
    const token: unknown = JSON.parse(json)
    validateToken(token)
    return token as HdpToken
  } catch (e) {
    throw new HdpSchemaError(`Failed to decode ${HDP_HEADER} header: ${(e as Error).message}`)
  }
}

/** Detect duplicate JSON object names before JSON.parse can discard them. */
function assertNoDuplicateObjectNames(json: string): void {
  let offset = 0

  const skipWhitespace = (): void => {
    while (/\s/.test(json[offset] ?? '')) offset++
  }

  const parseString = (): string => {
    const start = offset++
    while (offset < json.length) {
      if (json[offset] === '\\') {
        offset += 2
      } else if (json[offset++] === '"') {
        return JSON.parse(json.slice(start, offset)) as string
      }
    }
    throw new Error('unterminated JSON string')
  }

  const parseValue = (): void => {
    skipWhitespace()
    if (json[offset] === '{') {
      parseObject()
      return
    }
    if (json[offset] === '[') {
      offset++
      skipWhitespace()
      while (offset < json.length && json[offset] !== ']') {
        parseValue()
        skipWhitespace()
        if (json[offset] !== ',') break
        offset++
        skipWhitespace()
      }
      if (json[offset] === ']') offset++
      return
    }
    if (json[offset] === '"') {
      parseString()
      return
    }
    while (offset < json.length && !/[\s,}\]]/.test(json[offset])) offset++
  }

  const parseObject = (): void => {
    offset++
    skipWhitespace()
    const names = new Set<string>()
    while (offset < json.length && json[offset] !== '}') {
      if (json[offset] !== '"') return
      const name = parseString()
      if (names.has(name)) throw new Error(`duplicate JSON object member name '${name}'`)
      names.add(name)
      skipWhitespace()
      if (json[offset] !== ':') return
      offset++
      parseValue()
      skipWhitespace()
      if (json[offset] !== ',') break
      offset++
      skipWhitespace()
    }
    if (json[offset] === '}') offset++
  }

  parseValue()
}
