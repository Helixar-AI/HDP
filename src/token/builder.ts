import { v4 as uuidv4 } from 'uuid'
import type { HdpPrincipal, HdpScope, UnsignedToken } from '../types/token.js'

export class TokenBuilder {
  private _principal?: HdpPrincipal
  private _scope?: HdpScope
  // SDK fallback for backwards compatibility; HDP itself defines no default lifetime.
  private _expiresInMs = 24 * 60 * 60 * 1000

  constructor(private readonly sessionId: string) {}

  principal(p: HdpPrincipal): this {
    this._principal = p
    return this
  }

  scope(s: HdpScope): this {
    this._scope = s
    return this
  }

  expiresInMs(ms: number): this {
    this._expiresInMs = ms
    return this
  }

  build(): UnsignedToken {
    if (!this._principal) throw new Error('principal is required')
    if (!this._scope) throw new Error('scope is required')
    if (this.sessionId.length === 0) throw new Error('session_id must not be empty')
    if (!Number.isSafeInteger(this._expiresInMs) || this._expiresInMs <= 0) {
      throw new Error('expiresInMs must be a positive safe integer')
    }
    if (
      this._scope.max_hops !== undefined &&
      (!Number.isSafeInteger(this._scope.max_hops) || this._scope.max_hops < 1)
    ) {
      throw new Error('scope.max_hops must be a positive safe integer when present')
    }
    const now = Date.now()
    if (!Number.isSafeInteger(now + this._expiresInMs)) {
      throw new Error('expires_at exceeds the maximum safe JSON integer')
    }
    return {
      hdp: '0.1',
      header: {
        token_id: uuidv4(),
        issued_at: now,
        expires_at: now + this._expiresInMs,
        session_id: this.sessionId,
        version: '0.1',
      },
      principal: this._principal,
      scope: this._scope,
      chain: [],
    }
  }
}
