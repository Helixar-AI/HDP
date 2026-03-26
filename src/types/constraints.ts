export type DataClassification = 'public' | 'internal' | 'confidential' | 'restricted'
export type AgentType = 'orchestrator' | 'sub-agent' | 'tool-executor' | 'custom'
export type PrincipalIdType = 'email' | 'uuid' | 'did' | 'poh' | 'opaque'

export interface TimeWindowConstraint {
  type: 'time_window'
  params: { start: number; end: number }
}

export interface ResourceLimitConstraint {
  type: 'resource_limit'
  params: { resource: string; max_bytes: number }
}

export interface ActionCountConstraint {
  type: 'action_count'
  params: { tool: string; max_count: number }
}

export interface CustomConstraint {
  type: 'custom'
  params: { namespace: string; params: Record<string, unknown> }
}

export type ScopeConstraint =
  | TimeWindowConstraint
  | ResourceLimitConstraint
  | ActionCountConstraint
  | CustomConstraint
