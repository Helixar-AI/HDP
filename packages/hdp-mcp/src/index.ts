/**
 * @helixar_ai/hdp-mcp
 *
 * HDP middleware for MCP (Model Context Protocol) servers.
 *
 * Usage:
 *   const handler = hdpMiddleware(myToolHandler, { hdp_required: true, onValid: (token) => auditLog(token) })
 *   // handler is a drop-in replacement for myToolHandler
 */
import { verifyToken, decodeHeader } from '@helixar_ai/hdp'
import type { HdpToken, VerificationOptions } from '@helixar_ai/hdp'

export interface HdpMiddlewareOptions {
  /**
   * Verification options: publicKey and currentSessionId are required.
   * If omitted, middleware runs in pure observe mode (no verification).
   */
  verify?: VerificationOptions

  /**
   * When true, requests without a valid HDP token are rejected.
   * When false (default — observe mode), invalid/absent tokens are noted
   * but the handler is still called.
   */
  hdp_required?: boolean

  /**
   * Called when a valid HDP token is present.
   * Use for audit logging, telemetry, etc.
   */
  onValid?: (token: HdpToken) => void

  /**
   * Called when an HDP token is present but invalid.
   * Use for alerting, audit logging, etc.
   */
  onInvalid?: (error: Error) => void
}

export interface McpRequest {
  /** HTTP headers or MCP metadata. May contain X-HDP-Token. */
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
 * Wraps an MCP tool handler with HDP token inspection.
 *
 * In observe mode (default, hdp_required: false):
 *   - If a valid token is present, onValid is called
 *   - If no token or invalid token, the handler is still called
 *
 * In required mode (hdp_required: true):
 *   - Missing or invalid token returns { error: 'HDP token required' }
 *   - Valid token calls onValid then passes through to handler
 */
export function hdpMiddleware(
  handler: McpHandler,
  options: HdpMiddlewareOptions = {}
): McpHandler {
  const { verify, hdp_required = false, onValid, onInvalid } = options

  return async (request: McpRequest): Promise<McpResponse> => {
    const tokenHeader = request.headers?.['x-hdp-token'] ?? request.headers?.['X-HDP-Token']

    if (!tokenHeader) {
      if (hdp_required) {
        return { error: 'HDP_REQUIRED: X-HDP-Token header is required for this endpoint' }
      }
      // Observe mode: no token present, pass through
      return handler(request)
    }

    // Token present — attempt decode
    let token: HdpToken
    try {
      token = decodeHeader(tokenHeader)
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err))
      onInvalid?.(error)
      if (hdp_required) {
        return { error: `HDP_INVALID: Failed to decode token: ${error.message}` }
      }
      return handler(request)
    }

    // Verify if options provided
    if (verify) {
      const result = await verifyToken(token, verify)
      if (!result.valid) {
        const error = result.error ?? new Error('Token verification failed')
        onInvalid?.(error)
        if (hdp_required) {
          return { error: `HDP_INVALID: ${error.message}` }
        }
        return handler(request)
      }
    }

    // Valid token
    onValid?.(token)
    return handler(request)
  }
}

export type { HdpToken, VerificationOptions }
