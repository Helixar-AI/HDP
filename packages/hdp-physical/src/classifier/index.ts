// packages/hdp-physical/src/classifier/index.ts
import { CLASSIFICATION_RULES } from './rules.js'
import type { RobotAction, ClassificationResult } from '../types/classifier.js'

export class IrreversibilityClassifier {
  classify(action: RobotAction): ClassificationResult {
    for (const rule of CLASSIFICATION_RULES) {
      if (rule.match(action)) {
        return {
          action_class: rule.result_class,
          reason: rule.reason,
          triggered_rule: rule.id,
        }
      }
    }
    // Should never reach here — last rule is catch-all
    throw new Error('IrreversibilityClassifier: no rule matched (missing catch-all)')
  }
}
