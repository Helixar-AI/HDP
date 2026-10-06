/**
 * @helixar_ai/hdp-autogen
 *
 * HDP middleware for AutoGen — cryptographic audit trail for multi-agent delegation.
 *
 * Provides:
 *   - HdpAgentWrapper: stateful wrapper for AutoGen agent message flows
 *   - hdpMiddleware: functional wrapper matching hdp-mcp observe/required pattern
 *   - HDP_TOOLS / getHdpTools: OpenAI-compatible tool schemas for AutoGen function calling
 */
import {
  issueToken,
  extendChain,
  verifyToken,
  decodeHeader,
  encodeHeader,
  HDP_HEADER,
  HDP_LEGACY_HEADER,
  HdpError,
  HdpSchemaError,
} from '@helixar_ai/hdp'
import type {
  HdpToken,
  HdpScope,
  HdpPrincipal,
  VerificationOptions,
  VerificationResult,
  IssueTokenOptions,
  ChainExtensionRequest,
} from '@helixar_ai/hdp'

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/** @deprecated Scope findings are reported and never thrown by HDP adapters. */
export class HdpScopeViolationError extends Error {
  tool: string
  authorizedTools: string[]

  constructor(tool: string, authorizedTools: string[]) {
    super(`Tool '${tool}' is not in the authorized scope [${authorizedTools.join(', ')}]`)
    this.name = 'HdpScopeViolationError'
    this.tool = tool
    this.authorizedTools = authorizedTools
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HdpAgentOptions {
  /** Ed25519 private key (Uint8Array) */
  signingKey: Uint8Array
  /** Unique session identifier */
  sessionId: string
  /** Human principal delegating authority */
  principal: { id: string; id_type: string; display_name?: string }
  /** Scope metadata recorded on the token. */
  scope: {
    intent: string
    data_classification?: 'public' | 'internal' | 'confidential' | 'restricted'
    network_egress?: boolean
    persistence?: boolean
    authorized_tools?: string[]
    authorized_resources?: string[]
    max_hops?: number
  }
  /** Key identifier (default: "default") */
  keyId?: string
  /** Token lifetime in milliseconds (default: 86400000 = 24h) */
  expiresInMs?: number
  /** @deprecated Passing true throws because HDP records cannot gate tool calls. */
  strict?: boolean

  /** Called with out-of-scope tool findings. Findings do not stop tool calls. */
  onScopeViolation?: (finding: { tool: string; authorizedTools: string[] }) => void
}

export interface AutoGenMessage {
  /** Message content */
  content?: string
  /** Agent/sender name */
  name?: string
  /** Role (user, assistant, system, function) */
  role?: string
  /** OpenAI-style tool calls */
  tool_calls?: Array<{ function?: { name?: string } }>
  /** Legacy function call */
  function_call?: { name?: string }
  /** HDP token metadata */
  headers?: Record<string, string>
  /** Pass-through fields */
  [key: string]: unknown
}

export type AutoGenHandler = (message: AutoGenMessage) => Promise<AutoGenMessage>

export interface HdpMiddlewareOptions {
  /** Verification options for token validation */
  verify?: VerificationOptions
  /** @deprecated Passing true throws because HDP records cannot gate requests. */
  hdp_required?: boolean
  /** Called when decoding succeeds and any configured integrity check passes. */
  onValid?: (token: HdpToken) => void
  /** Called when token decoding or integrity verification finds an issue */
  onInvalid?: (result: VerificationResult) => void
  /** Called when the message has no HDP token. */
  onMissing?: () => void
}

// ---------------------------------------------------------------------------
// HdpAgentWrapper — stateful wrapper for AutoGen agent flows
// ---------------------------------------------------------------------------

export class HdpAgentWrapper {
  private token: HdpToken | null = null
  private readonly signingKey: Uint8Array
  private readonly sessionId: string
  private readonly principal: { id: string; id_type: string; display_name?: string }
  private readonly scope: HdpAgentOptions['scope']
  private readonly keyId: string
  private readonly expiresInMs: number
  private readonly onScopeViolation?: HdpAgentOptions['onScopeViolation']
  private hopCount = 0

  constructor(options: HdpAgentOptions) {
    if (options.strict === true) {
      throw new Error('HDP tokens are records and cannot gate tool calls')
    }
    this.signingKey = options.signingKey
    this.sessionId = options.sessionId
    this.principal = options.principal
    this.scope = options.scope
    this.keyId = options.keyId ?? 'default'
    this.expiresInMs = options.expiresInMs ?? 24 * 60 * 60 * 1000
    this.onScopeViolation = options.onScopeViolation
  }

  /**
   * Issue the root HDP token. Call before the first speaker turn.
   */
  async init(): Promise<void> {
    const hdpScope: HdpScope = {
      intent: this.scope.intent,
      data_classification: this.scope.data_classification ?? 'internal',
      network_egress: this.scope.network_egress ?? true,
      persistence: this.scope.persistence ?? false,
      authorized_tools: this.scope.authorized_tools,
      authorized_resources: this.scope.authorized_resources,
      max_hops: this.scope.max_hops,
    }

    this.token = await issueToken({
      sessionId: this.sessionId,
      principal: this.principal as HdpPrincipal,
      scope: hdpScope,
      signingKey: this.signingKey,
      keyId: this.keyId,
      expiresInMs: this.expiresInMs,
    })
    this.hopCount = 0
  }

  /**
   * Record a speaker turn as a delegation hop.
   * Each GroupChat speaker selection maps to one hop.
   */
  async onSpeakerTurn(agentId: string, message: string): Promise<void> {
    try {
      if (!this.token) {
        await this.init()
      }

      const maxHops = this.scope.max_hops
      if (maxHops !== undefined && this.hopCount >= maxHops) {
        return
      }

      this.hopCount++
      const ext: ChainExtensionRequest = {
        agent_id: agentId,
        agent_type: 'sub-agent',
        action_summary: message.slice(0, 200),
        parent_hop: this.hopCount - 1,
      }

      this.token = await extendChain(this.token!, ext, this.signingKey)
    } catch {
      // Non-blocking: signing failures are silently absorbed so agent
      // execution is never halted by HDP instrumentation.
    }
  }

  /**
   * Report whether a tool call is outside the recorded authorized_tools list.
   * This finding does not gate the tool call.
   */
  onToolCall(tool: string): void {
    const authorized = this.scope.authorized_tools
    if (authorized === undefined) return

    if (!authorized.includes(tool)) {
      try {
        this.onScopeViolation?.({ tool, authorizedTools: [...authorized] })
      } catch (error) {
        console.error('HDP scope violation callback failed:', error)
      }
    }
  }

  /** Return the current token, or null before init(). */
  exportToken(): HdpToken | null {
    return this.token
  }

  /** Return the token as a JSON string, or null before init(). */
  exportTokenJson(indent = 2): string | null {
    if (!this.token) return null
    return JSON.stringify(this.token, null, indent)
  }
}

// ---------------------------------------------------------------------------
// hdpMiddleware — functional wrapper matching hdp-mcp pattern
// ---------------------------------------------------------------------------

/**
 * Wraps an AutoGen message handler with record inspection. Token findings are
 * reported to callbacks and never condition whether the handler runs.
 */
export function hdpMiddleware(
  handler: AutoGenHandler,
  options: HdpMiddlewareOptions = {}
): AutoGenHandler {
  const { verify, hdp_required, onValid, onInvalid, onMissing } = options
  if (hdp_required === true) {
    throw new Error('HDP tokens are records and cannot gate requests')
  }

  return async (message: AutoGenMessage): Promise<AutoGenMessage> => {
    const tokenHeader = readTokenHeader(message.headers)

    if (!tokenHeader) {
      notifyCallback(onMissing)
      return handler(message)
    }

    let token: HdpToken
    try {
      token = decodeHeader(tokenHeader)
    } catch (err) {
      notifyCallbackResult(onInvalid, invalidInputResult(err))
      return handler(message)
    }

    if (verify) {
      const result = await verifyToken(token, verify)
      if (!result.valid) {
        notifyCallbackResult(onInvalid, result)
        return handler(message)
      }
    }

    notifyCallbackResult(onValid, token)
    return handler(message)
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

// ---------------------------------------------------------------------------
// HDP_TOOLS — OpenAI-compatible tool schemas for AutoGen function calling
// ---------------------------------------------------------------------------

export const HDP_TOOLS = [
  {
    type: 'function' as const,
    function: {
      name: 'hdp_issue_token',
      description:
        'Issue a new root HDP token when human delegation begins. ' +
        'Use at the start of a session or when the user authorises a new task.',
      parameters: {
        type: 'object',
        properties: {
          scope: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional action scope labels recorded in the token',
          },
          expires_in: {
            type: 'integer',
            description: 'Optional token lifetime in seconds (default: 3600)',
          },
        },
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'hdp_extend_chain',
      description:
        'Extend the delegation chain when handing off to a sub-agent or external tool.',
      parameters: {
        type: 'object',
        properties: {
          delegatee_id: {
            type: 'string',
            description: 'Identifier of the receiving agent or tool',
          },
          additional_scope: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional scope labels to record with this hop',
          },
        },
        required: ['delegatee_id'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'hdp_verify_token',
      description:
        'Inspect an HDP token and return provenance details for audit. ' +
        'The result must not gate an action.',
      parameters: {
        type: 'object',
        properties: {
          token: {
            type: 'string',
            description: 'The HDP token string to verify',
          },
        },
        required: ['token'],
      },
    },
  },
]

/** Return HDP_TOOLS — convenience alias. */
export function getHdpTools(): typeof HDP_TOOLS {
  return HDP_TOOLS
}

// ---------------------------------------------------------------------------
// Re-exports from core
// ---------------------------------------------------------------------------

export type { HdpToken, VerificationOptions, HdpScope, HdpPrincipal }
export { encodeHeader, decodeHeader }
