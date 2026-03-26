import type { AgentType } from './constraints.js'

export interface HopRecord {
  seq: number
  agent_id: string
  agent_type: AgentType
  agent_fingerprint?: string
  timestamp: number
  action_summary: string
  parent_hop: number
  /** Required on all hop records in a finalized chain. Spec Section 6.3 Rule 6: MUST be included. */
  hop_signature: string
  [key: `x-${string}`]: unknown
}

/** Pre-signing hop — hop_signature is absent until signHop() is called */
export type UnsignedHopRecord = Omit<HopRecord, 'hop_signature'>

export interface ChainExtensionRequest {
  agent_id: string
  agent_type: AgentType
  agent_fingerprint?: string
  action_summary: string
  parent_hop: number
}

export interface ReAuthRequest {
  parent_token_id: string
  reason: 'max_hops_exceeded' | 'scope_insufficient'
}
