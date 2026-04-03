// packages/hdp-physical/src/classifier/rules.ts
import { IrreversibilityClass } from '../types/edt.js'
import type { RobotAction, ClassificationResult } from '../types/classifier.js'

// Max safe values — thresholds relative to these
const MAX_FORCE_N = 45.0
const MAX_VELOCITY_MS = 0.5

type Rule = {
  id: string
  description: string
  match: (action: RobotAction) => boolean
  result_class: IrreversibilityClass
  reason: string
}

export const CLASSIFICATION_RULES: Rule[] = [
  // Class 3 — check first (most dangerous wins)
  {
    id: 'force_max',
    description: 'Force at or above 95% of maximum',
    match: (a) => a.force_n !== undefined && a.force_n >= MAX_FORCE_N * 0.95,
    result_class: IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
    reason: 'Force at or above 95% of safe maximum — irreversible and harmful',
  },
  {
    id: 'velocity_max',
    description: 'Velocity at or above 90% of maximum',
    match: (a) => a.velocity_ms !== undefined && a.velocity_ms >= MAX_VELOCITY_MS * 0.90,
    result_class: IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
    reason: 'Velocity at or above 90% of safe maximum — risk of uncontrolled movement',
  },
  {
    id: 'dangerous_keywords',
    description: 'Description contains dangerous action keywords',
    match: (a) =>
      /crush|harm|dangerous|override|ignore.*safety|ignore.*limit|max.*speed|max.*velocity/i.test(
        a.description
      ),
    result_class: IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
    reason: 'Action description contains dangerous command keywords',
  },
  {
    id: 'explicit_max_params',
    description: 'Structured command with force=1.0 or velocity=2.0',
    match: (a) =>
      /gripper_force=1\.0|velocity=2\.0/i.test(a.description),
    result_class: IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
    reason: 'Structured command requests maximum unsafe parameters',
  },
  // Class 2 — irreversible but not immediately harmful
  {
    id: 'force_high',
    description: 'Force between 80% and 95% of maximum',
    match: (a) =>
      a.force_n !== undefined &&
      a.force_n >= MAX_FORCE_N * 0.80 &&
      a.force_n < MAX_FORCE_N * 0.95,
    result_class: IrreversibilityClass.IRREVERSIBLE_NORMALLY,
    reason: 'Force exceeds 80% of safe maximum — action may be irreversible',
  },
  {
    id: 'irreversible_keywords',
    description: 'Description contains irreversible action keywords',
    match: (a) =>
      /press.fit|permanent|bond|cut|laser|weld|solder|seal/i.test(a.description),
    result_class: IrreversibilityClass.IRREVERSIBLE_NORMALLY,
    reason: 'Action description indicates an irreversible physical operation',
  },
  // Class 0 — read-only / observation
  {
    id: 'sensor_query',
    description: 'Read-only sensor or state query',
    match: (a) =>
      /sensor|query|read|observe|detect|measure|what is|status|state\?/i.test(a.description) &&
      !/\bpick\b|\bplace\b|\bmove\b|\brotate\b|\bgrip\b/i.test(a.description),
    result_class: IrreversibilityClass.REVERSIBLE,
    reason: 'Read-only sensor query — no physical state change',
  },
  // Class 1 — default for normal manipulation
  {
    id: 'default_manipulation',
    description: 'Standard pick-and-place or movement within safe limits',
    match: () => true,   // catch-all
    result_class: IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
    reason: 'Standard manipulation action within safe parameters',
  },
]

// Export type for use in classifier index
export type { ClassificationResult }
