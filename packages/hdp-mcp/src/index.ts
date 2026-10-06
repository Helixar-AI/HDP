/**
 * @helixar_ai/hdp-mcp
 *
 * HDP middleware for MCP (Model Context Protocol) servers.
 *
 * Usage:
 *   const handler = hdpMiddleware(myToolHandler, { verify: { publicKey }, onValid: (token) => auditLog(token) })
 *   // handler is a drop-in replacement for myToolHandler
 */
import {
  verifyToken,
  decodeHeader,
  HDP_HEADER,
  HDP_LEGACY_HEADER,
  HdpError,
  HdpSchemaError,
} from '@helixar_ai/hdp'
import type { HdpToken, VerificationOptions, VerificationResult } from '@helixar_ai/hdp'

export interface HdpMiddlewareOptions {
  /**
   * Verification options contain the issuer public key.
   * If omitted, middleware decodes records without checking signatures.
   */
  verify?: VerificationOptions

  /**
   * @deprecated Passing true throws because HDP records cannot gate requests.
   */
  hdp_required?: boolean

  /**
   * Called when token decoding succeeds and any configured integrity check passes.
   * Use for audit logging, telemetry, etc.
   */
  onValid?: (token: HdpToken) => void

  /**
   * Called when token decoding or integrity verification finds an issue.
   * Use for alerting, audit logging, etc.
   */
  onInvalid?: (result: VerificationResult) => void

  /** Called when the request has no HDP token. */
  onMissing?: () => void
}

export interface McpRequest {
  /** HTTP headers or MCP metadata. HDP-Token is standard; X-HDP-Token is a deprecated input alias. */
  headers?: Record<string, string>
  /** MCP tool name */
  tool?: string
  /** MCP tool arguments */
  params?: unknown
}

export interface McpResponse {
  error?: string
  [key: string]: unknown
}

export type McpHandler = (request: McpRequest) => Promise<McpResponse>

/**
 * Wraps an MCP tool handler with record inspection. Token findings are
 * reported to callbacks and never condition whether the handler runs.
 */
export function hdpMiddleware(
  handler: McpHandler,
  options: HdpMiddlewareOptions = {}
): McpHandler {
  const { verify, hdp_required, onValid, onInvalid, onMissing } = options
  if (hdp_required === true) {
    throw new Error('HDP tokens are records and cannot gate requests')
  }

  return async (request: McpRequest): Promise<McpResponse> => {
    const tokenHeader = readTokenHeader(request.headers)

    if (!tokenHeader) {
      notifyCallback(onMissing)
      return handler(request)
    }

    // Token present — attempt decode
    let token: HdpToken
    try {
      token = decodeHeader(tokenHeader)
    } catch (err) {
      notifyCallbackResult(onInvalid, invalidInputResult(err))
      return handler(request)
    }

    // Verify if options provided
    if (verify) {
      const result = await verifyToken(token, verify)
      if (!result.valid) {
        notifyCallbackResult(onInvalid, result)
        return handler(request)
      }
    }

    // Decoded record and, if configured, integrity-verified record.
    notifyCallbackResult(onValid, token)
    return handler(request)
  }
}

function notifyCallback(callback: (() => void) | undefined): void {
  try {
    callback?.()
  } catch (error) {
    console.error('HDP middleware callback failed:', error)
  }
}

function notifyCallbackResult<T>(callback: ((value: T) => void) | undefined, value: T): void {
  try {
    callback?.(value)
  } catch (error) {
    console.error('HDP middleware callback failed:', error)
  }
}

function invalidInputResult(error: unknown): VerificationResult {
  return {
    valid: false,
    failedStep: 0,
    error: error instanceof HdpError
      ? error
      : new HdpSchemaError(error instanceof Error ? error.message : String(error)),
  }
}

/**
 * HTTP field names are case-insensitive. Prefer the standard name and only
 * fall back to the deprecated X-prefixed alias for inbound compatibility.
 */
function readTokenHeader(headers: Record<string, string> | undefined): string | undefined {
  if (!headers) return undefined

  let legacy: string | undefined
  for (const [name, value] of Object.entries(headers)) {
    const normalized = name.toLowerCase()
    if (normalized === HDP_HEADER.toLowerCase()) return value
    if (normalized === HDP_LEGACY_HEADER.toLowerCase()) legacy = value
  }
  return legacy
}

export type { HdpToken, VerificationOptions }
