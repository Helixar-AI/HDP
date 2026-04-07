// packages/hdp-physical/src/types/edt.ts

export enum IrreversibilityClass {
  REVERSIBLE = 0,
  REVERSIBLE_WITH_EFFORT = 1,
  IRREVERSIBLE_NORMALLY = 2,
  IRREVERSIBLE_AND_HARMFUL = 3,
}

export interface EmbodimentSpec {
  agent_type: string        // e.g. "robot_arm"
  platform_id: string       // e.g. "aloha_v2"
  hardware_id?: string      // TPM-bindable hardware identifier
  workspace_scope: string   // e.g. "conveyor_zone_A"
}

export interface ActionScope {
  permitted_actions: string[]   // e.g. ["pick", "place", "move"]
  excluded_zones: string[]      // e.g. ["human_proximity_zone"]
  max_force_n: number           // Newtons ceiling
  max_velocity_ms: number       // metres/second ceiling
}

export interface IrreversibilitySpec {
  max_class: IrreversibilityClass
  class2_requires_confirmation: boolean
  class3_prohibited: boolean
}

export interface PolicyAttestation {
  policy_hash: string       // SHA-256 hex of deployed policy weights
  training_run_id: string
  sim_validated: boolean
}

export interface DelegationScope {
  allow_fleet_delegation: boolean
  max_delegation_depth: number
  sub_agent_whitelist: string[]
}

export interface EdtToken {
  embodiment: EmbodimentSpec
  action_scope: ActionScope
  irreversibility: IrreversibilitySpec
  policy_attestation: PolicyAttestation
  delegation_scope: DelegationScope
}

export interface SignedEdt {
  edt: EdtToken
  signature: string   // Ed25519 over RFC-8785 canonical JSON of edt, base64url
  kid: string         // Key identifier
  alg: 'Ed25519'
}
