// packages/hdp-physical/src/types/classifier.ts
import type { IrreversibilityClass } from './edt.js'

export interface RobotAction {
  description: string       // Human-readable action description
  force_n?: number          // Estimated force in Newtons (if known)
  velocity_ms?: number      // Estimated velocity in m/s (if known)
  zone?: string             // Target zone identifier (if known)
}

export interface ClassificationResult {
  action_class: IrreversibilityClass
  reason: string            // Human-readable explanation
  triggered_rule: string    // Which rule fired (e.g. "force_ceiling_95pct")
}
