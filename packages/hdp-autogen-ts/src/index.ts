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
  /** Authorization scope */
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
  /** Raise on scope violations instead of logging (default: false) */
  strict?: boolean
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
  /** When true, messages without a valid HDP token are rejected (default: false) */
  hdp_required?: boolean
  /** Called when a valid HDP token is present */
  onValid?: (token: HdpToken) => void
  /** Called when an HDP token is present but invalid */
  onInvalid?: (error: Error) => void
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
  private readonly strict: boolean
  private hopCount = 0

  constructor(options: HdpAgentOptions) {
    this.signingKey = options.signingKey
    this.sessionId = options.sessionId
    this.principal = options.principal
    this.scope = options.scope
    this.keyId = options.keyId ?? 'default'
    this.expiresInMs = options.expiresInMs ?? 24 * 60 * 60 * 1000
    this.strict = options.strict ?? false
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
  }

  /**
   * Validate a tool call against authorized_tools.
   * In strict mode, throws HdpScopeViolationError.
   */
  onToolCall(tool: string): void {
    const authorized = this.scope.authorized_tools
    if (authorized === undefined) return

    if (!authorized.includes(tool)) {
      if (this.strict) {
        throw new HdpScopeViolationError(tool, authorized)
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
 * Wraps an AutoGen message handler with HDP token inspection.
 *
 * In observe mode (default, hdp_required: false):
 *   - If a valid token is present in message headers, onValid is called
 *   - If no token or invalid token, the handler is still called
 *
 * In required mode (hdp_required: true):
 *   - Missing or invalid token returns { error: 'HDP token required' }
 *   - Valid token calls onValid then passes through to handler
 */
export function hdpMiddleware(
  handler: AutoGenHandler,
  options: HdpMiddlewareOptions = {}
): AutoGenHandler {
  const { verify, hdp_required = false, onValid, onInvalid } = options

  return async (message: AutoGenMessage): Promise<AutoGenMessage> => {
    const tokenHeader = message.headers?.['x-hdp-token'] ?? message.headers?.['X-HDP-Token']

    if (!tokenHeader) {
      if (hdp_required) {
        return { error: 'HDP_REQUIRED: X-HDP-Token header is required' } as unknown as AutoGenMessage
      }
      return handler(message)
    }

    let token: HdpToken
    try {
      token = decodeHeader(tokenHeader)
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err))
      onInvalid?.(error)
      if (hdp_required) {
        return { error: `HDP_INVALID: Failed to decode token: ${error.message}` } as unknown as AutoGenMessage
      }
      return handler(message)
    }

    if (verify) {
      const result = await verifyToken(token, verify)
      if (!result.valid) {
        const error = result.error ?? new Error('Token verification failed')
        onInvalid?.(error)
        if (hdp_required) {
          return { error: `HDP_INVALID: ${error.message}` } as unknown as AutoGenMessage
        }
        return handler(message)
      }
    }

    onValid?.(token)
    return handler(message)
  }
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
            description: 'Optional list of permitted action scopes',
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
            description: 'Any extra permissions for this hop',
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
        'Verify an HDP token before performing sensitive actions. ' +
        'Returns full provenance details.',
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
