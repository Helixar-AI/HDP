// HDP Reference Implementation — Public API
// Spec: https://helixar.ai/labs/hdp

// Types
export type {
  HdpToken, HdpHeader, HdpPrincipal, HdpScope, HdpSignature, UnsignedToken
} from './types/token.js'
export type { HopRecord, UnsignedHopRecord, ChainExtensionRequest, ReAuthRequest } from './types/chain.js'
export type {
  ScopeConstraint, TimeWindowConstraint, ResourceLimitConstraint,
  ActionCountConstraint, DataClassification, AgentType, PrincipalIdType
} from './types/constraints.js'
export {
  HdpError, HdpTokenExpiredError, HdpSignatureInvalidError,
  HdpChainIntegrityError, HdpSessionMismatchError, HdpMaxHopsExceededError, HdpSchemaError
} from './types/errors.js'

// Schema validation
export { validateToken } from './schema/validator.js'

// Key management
export { generateKeyPair, exportPublicKey, importPublicKey, exportPrivateKey, importPrivateKey } from './crypto/keys.js'

// Token lifecycle
export { TokenBuilder } from './token/builder.js'
export { issueToken } from './token/issuer.js'
export type { IssueTokenOptions } from './token/issuer.js'
export { verifyToken } from './token/verifier.js'
export type { VerificationOptions, VerificationResult } from './token/verifier.js'

// Chain management
export { extendChain } from './chain/extender.js'
export { validateChain } from './chain/validator.js'

// Transport
export { encodeHeader, decodeHeader, HDP_HEADER, HDP_REF_HEADER } from './transport/http.js'
export type { TokenStore } from './transport/store.js'
export { InMemoryTokenStore } from './transport/store.js'
export { storeToken, resolveToken } from './transport/reference.js'

// Privacy
export { stripPrincipal, buildAuditSafe, redactPii } from './privacy/redactor.js'
export type { AuditSafeToken } from './privacy/redactor.js'
export { isRetentionExpired, deleteToken } from './privacy/retention.js'
