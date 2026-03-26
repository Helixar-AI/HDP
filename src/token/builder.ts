import { v4 as uuidv4 } from 'uuid'
import type { HdpPrincipal, HdpScope, UnsignedToken } from '../types/token.js'

export class TokenBuilder {
  private _principal?: HdpPrincipal
  private _scope?: HdpScope
  private _expiresInMs = 24 * 60 * 60 * 1000 // 24h default

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
    const now = Date.now()
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
