// packages/hdp-physical/src/guard/index.ts
import { IrreversibilityClass } from '../types/edt.js'
import { IrreversibilityClassifier } from '../classifier/index.js'
import { verifyEdt } from '../edt/verifier.js'
import type { SignedEdt } from '../types/edt.js'
import type { RobotAction } from '../types/classifier.js'
import type { AuthorizationDecision, BlockedAt } from '../types/guard.js'

const classifier = new IrreversibilityClassifier()

function block(
  reason: string,
  blockedAt: Exclude<BlockedAt, null>,
  actionClass: IrreversibilityClass,
  edtValid: boolean
): AuthorizationDecision {
  return { approved: false, classification: actionClass, reason, edt_valid: edtValid, blocked_at: blockedAt }
}

export class PreExecutionGuard {
  async authorize(
    action: RobotAction,
    signedEdt: SignedEdt | null,
    publicKey: Uint8Array
  ): Promise<AuthorizationDecision> {
    // Step 1: signature check
    if (signedEdt === null) {
      return block('No EDT provided — all unsigned commands are Class 3 blocks', 'signature', IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL, false)
    }
    const edtValid = await verifyEdt(signedEdt, publicKey)
    if (!edtValid) {
      return block('EDT signature verification failed — command rejected', 'signature', IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL, false)
    }

    // Step 2: classify action
    const { action_class, reason } = classifier.classify(action)

    // Step 3: class3_prohibited check
    if (action_class === IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL && signedEdt.edt.irreversibility.class3_prohibited) {
      return block(`Class 3 action rejected: ${reason}`, 'class3_prohibited', action_class, true)
    }

    // Step 4: class ceiling check
    if (action_class > signedEdt.edt.irreversibility.max_class) {
      return block(
        `Action class ${action_class} exceeds EDT ceiling of ${signedEdt.edt.irreversibility.max_class}`,
        'class_ceiling',
        action_class,
        true
      )
    }

    // Step 5: excluded zone check
    if (action.zone && signedEdt.edt.action_scope.excluded_zones.includes(action.zone)) {
      return block(`Zone "${action.zone}" is excluded by EDT`, 'excluded_zone', action_class, true)
    }

    // Step 6: force limit check
    if (action.force_n !== undefined && action.force_n > signedEdt.edt.action_scope.max_force_n) {
      return block(
        `Force ${action.force_n}N exceeds EDT limit of ${signedEdt.edt.action_scope.max_force_n}N`,
        'force_limit',
        action_class,
        true
      )
    }

    // Step 7: velocity limit check
    if (action.velocity_ms !== undefined && action.velocity_ms > signedEdt.edt.action_scope.max_velocity_ms) {
      return block(
        `Velocity ${action.velocity_ms}m/s exceeds EDT limit of ${signedEdt.edt.action_scope.max_velocity_ms}m/s`,
        'velocity_limit',
        action_class,
        true
      )
    }

    return { approved: true, classification: action_class, reason, edt_valid: true, blocked_at: null }
  }
}
