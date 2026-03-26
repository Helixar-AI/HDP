import type { HdpToken } from '../types/token.js'

/** Returns token with principal section removed — for external MCP/tool transmission */
export function stripPrincipal(token: HdpToken): Omit<HdpToken, 'principal'> {
  const { principal: _, ...rest } = token
  return rest
}

export interface AuditSafeToken {
  token_id: string
  intent: string
  chain: Array<{ seq: number; agent_id: string; agent_type: string }>
}

/** Returns a minimal audit-safe object: only token_id, chain seq/agent_id, and scope.intent */
export function buildAuditSafe(token: HdpToken): AuditSafeToken {
  return {
    token_id: token.header.token_id,
    intent: token.scope.intent,
    chain: token.chain.map(h => ({ seq: h.seq, agent_id: h.agent_id, agent_type: h.agent_type })),
  }
}

/**
 * Anonymizes PII fields in the principal section while preserving token structure.
 * Use when you need to retain the token shape for forensic purposes but must
 * remove personal identifiers (GDPR Article 17 partial erasure).
 */
export function redactPii(token: HdpToken): HdpToken {
  const { display_name: _, ...restPrincipal } = token.principal
  return {
    ...token,
    principal: {
      ...restPrincipal,
      id: '[REDACTED]',
    },
  }
}
