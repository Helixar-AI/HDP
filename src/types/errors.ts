export class HdpError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message)
    this.name = 'HdpError'
  }
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp)
  return Number.isNaN(date.getTime()) ? String(timestamp) : date.toISOString()
}

export class HdpTokenExpiredError extends HdpError {
  constructor(expiresAt: number) {
    super(`Token expired at ${formatTimestamp(expiresAt)}`, 'TOKEN_EXPIRED')
  }
}

export class HdpTokenNotYetValidError extends HdpError {
  constructor(issuedAt: number) {
    super(`Token is not valid before ${formatTimestamp(issuedAt)}`, 'TOKEN_NOT_YET_VALID')
  }
}

export class HdpTokenRevokedError extends HdpError {
  constructor(tokenId: string) {
    super(`Token has been revoked: ${tokenId}`, 'TOKEN_REVOKED')
  }
}

export class HdpUnsupportedVersionError extends HdpError {
  constructor(version: unknown) {
    super(`Unsupported HDP version: ${String(version)}`, 'UNSUPPORTED_VERSION')
  }
}

export class HdpVersionMismatchError extends HdpError {
  constructor(hdp: unknown, headerVersion: unknown) {
    super(`Token version mismatch: hdp=${String(hdp)}, header.version=${String(headerVersion)}`, 'VERSION_MISMATCH')
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

export class HdpPresenterMismatchError extends HdpError {
  constructor(expected: string, actual?: string) {
    super(
      actual === undefined
        ? `Token has no authenticated presenter; expected agent_id '${expected}'`
        : `Token presenter '${actual}' does not match expected agent_id '${expected}'`,
      'PRESENTER_MISMATCH',
    )
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
