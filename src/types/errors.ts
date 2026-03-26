export class HdpError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message)
    this.name = 'HdpError'
  }
}

export class HdpTokenExpiredError extends HdpError {
  constructor(expiresAt: number) {
    super(`Token expired at ${new Date(expiresAt).toISOString()}`, 'TOKEN_EXPIRED')
  }
}

export class HdpSignatureInvalidError extends HdpError {
  constructor(detail: string) {
    super(`Signature invalid: ${detail}`, 'SIGNATURE_INVALID')
  }
}

export class HdpChainIntegrityError extends HdpError {
  constructor(detail: string) {
    super(`CHAIN_INTEGRITY: Chain integrity failure: ${detail}`, 'CHAIN_INTEGRITY')
  }
}

export class HdpSessionMismatchError extends HdpError {
  constructor() {
    super('Token session_id does not match current session', 'SESSION_MISMATCH')
  }
}

export class HdpMaxHopsExceededError extends HdpError {
  constructor(max: number) {
    super(`MAX_HOPS_EXCEEDED: Delegation chain exceeds max_hops limit of ${max}`, 'MAX_HOPS_EXCEEDED')
  }
}

export class HdpSchemaError extends HdpError {
  constructor(details: string) {
    super(`SCHEMA_INVALID: Token schema validation failed: ${details}`, 'SCHEMA_INVALID')
  }
}
