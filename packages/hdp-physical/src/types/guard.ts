// packages/hdp-physical/src/types/guard.ts
import type { IrreversibilityClass } from './edt.js'

export type BlockedAt =
  | 'signature'
  | 'class_ceiling'
  | 'class3_prohibited'
  | 'excluded_zone'
  | 'force_limit'
  | 'velocity_limit'
  | null

export interface AuthorizationDecision {
  approved: boolean
  classification: IrreversibilityClass
  reason: string
  edt_valid: boolean
  blocked_at: BlockedAt
}
