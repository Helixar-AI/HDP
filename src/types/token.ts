import type { DataClassification, PrincipalIdType, ScopeConstraint } from './constraints.js'

export interface HdpHeader {
  token_id: string
  issued_at: number
  expires_at: number
  session_id: string
  version: string
  parent_token_id?: string
}

export interface HdpPrincipal {
  id: string
  id_type: PrincipalIdType
  poh_credential?: string
  display_name?: string
  metadata?: Record<string, unknown>
}

export interface HdpScope {
  intent: string
  authorized_tools?: string[]
  authorized_resources?: string[]
  data_classification: DataClassification
  network_egress: boolean
  persistence: boolean
  max_hops?: number
  constraints?: ScopeConstraint[]
  extensions?: Record<string, unknown>
}

export interface HdpSignature {
  alg: 'Ed25519' | 'ES256'
  kid: string
  value: string
  signed_fields: ['header', 'principal', 'scope']
}

export interface HdpToken {
  hdp: '0.1'
  header: HdpHeader
  principal: HdpPrincipal
  scope: HdpScope
  chain: import('./chain.js').HopRecord[]
  signature: HdpSignature
}

/** Token without signature — used during construction */
export type UnsignedToken = Omit<HdpToken, 'signature'>
