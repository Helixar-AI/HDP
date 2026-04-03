// packages/hdp-physical/src/index.ts

// Types
export { IrreversibilityClass } from './types/edt.js'
export type {
  EdtToken,
  EmbodimentSpec,
  ActionScope,
  IrreversibilitySpec,
  PolicyAttestation,
  DelegationScope,
  SignedEdt,
} from './types/edt.js'
export type { RobotAction, ClassificationResult } from './types/classifier.js'
export type { AuthorizationDecision, BlockedAt } from './types/guard.js'

// EDT
export { EdtBuilder } from './edt/builder.js'
export { signEdt, canonicalizeEdt } from './edt/signer.js'
export { verifyEdt } from './edt/verifier.js'
export { edtToHdpExtension, edtFromHdpExtension } from './edt/bridge.js'

// Classifier
export { IrreversibilityClassifier } from './classifier/index.js'

// Guard
export { PreExecutionGuard } from './guard/index.js'

// Chain
export { generateMermaidDiagram } from './chain/diagram.js'
