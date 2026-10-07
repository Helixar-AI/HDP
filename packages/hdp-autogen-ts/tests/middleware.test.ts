import { describe, it, expect, vi } from 'vitest'
import { HdpAgentWrapper, hdpMiddleware, HDP_TOOLS, getHdpTools, type AutoGenMessage } from '../src/index.js'
import { generateKeyPair, issueToken, extendChain, verifyToken, encodeHeader } from '@helixar_ai/hdp'

async function makeWrapper(overrides: Record<string, unknown> = {}) {
  const { privateKey, publicKey } = await generateKeyPair()
  const wrapper = new HdpAgentWrapper({
    signingKey: privateKey,
    sessionId: 'sess-autogen-test',
    principal: { id: 'usr_test', id_type: 'opaque' },
    scope: {
      intent: 'test',
      data_classification: 'public',
      network_egress: false,
      persistence: false,
      ...overrides,
    },
    ...overrides,
  })
  return { wrapper, privateKey, publicKey }
}

async function makeToken(expiresInMs = 24 * 60 * 60 * 1000) {
  const { privateKey, publicKey } = await generateKeyPair()
  const token = await issueToken({
    sessionId: 'sess-autogen-test',
    principal: { id: 'usr_test', id_type: 'opaque' },
    scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
    signingKey: privateKey, keyId: 'k1', expiresInMs,
  })
  return { token, privateKey, publicKey }
}

// ---------------------------------------------------------------------------
// HdpAgentWrapper
// ---------------------------------------------------------------------------

describe('HdpAgentWrapper', () => {
  it('issues root token on init', async () => {
    const { wrapper } = await makeWrapper()
    await wrapper.init()
    const token = wrapper.exportToken()
    expect(token).not.toBeNull()
    expect(token!.header.session_id).toBe('sess-autogen-test')
    expect(token!.chain).toHaveLength(0)
  })

  it('rejects an invalid custom principal id_type during construction', async () => {
    const { privateKey } = await generateKeyPair()

    expect(() => new HdpAgentWrapper({
      signingKey: privateKey,
      sessionId: 'sess-autogen-invalid-config',
      principal: { id: 'usr_test', id_type: 'x-a\rb' },
      scope: { intent: 'test' },
    })).toThrow()
  })

  it('rejects an invalid scope during construction', async () => {
    const { privateKey } = await generateKeyPair()

    expect(() => new HdpAgentWrapper({
      signingKey: privateKey,
      sessionId: 'sess-autogen-invalid-scope',
      principal: { id: 'usr_test', id_type: 'opaque' },
      scope: { intent: 'test', max_hops: 0 },
    })).toThrow()
  })

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER])(
    'rejects invalid expiresInMs %s during construction',
    async (expiresInMs) => {
      const { privateKey } = await generateKeyPair()

      expect(() => new HdpAgentWrapper({
        signingKey: privateKey,
        sessionId: 'sess-autogen-invalid-ttl',
        principal: { id: 'usr_test', id_type: 'opaque' },
        scope: { intent: 'test' },
        expiresInMs,
      })).toThrow()
    }
  )

  it('logs root issuance failure and lets the speaker action continue', async () => {
    const { privateKey } = await generateKeyPair()
    const principal = { id: 'usr_test', id_type: 'opaque' }
    const wrapper = new HdpAgentWrapper({
      signingKey: privateKey,
      sessionId: 'sess-autogen-runtime-failure',
      principal,
      scope: { intent: 'test' },
    })
    const logWarning = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const downstream = vi.fn().mockResolvedValue('agent result')

    principal.id_type = 'x-a\rb'

    try {
      await wrapper.onSpeakerTurn('agent', 'speaker turn')
      const result = await downstream()

      expect(result).toBe('agent result')
      expect(downstream).toHaveBeenCalledOnce()
      expect(wrapper.exportToken()).toBeNull()
      expect(logWarning.mock.calls).toEqual([['HDP root record issuance failed; action continues']])
    } finally {
      logWarning.mockRestore()
    }
  })

  it('records speaker turns as hops', async () => {
    const { wrapper, publicKey } = await makeWrapper()
    await wrapper.init()
    await wrapper.onSpeakerTurn('researcher', 'Found relevant papers')
    await wrapper.onSpeakerTurn('reviewer', 'Methodology looks sound')

    const token = wrapper.exportToken()!
    expect(token.chain).toHaveLength(2)
    expect(token.chain[0].agent_id).toBe('researcher')
    expect(token.chain[1].agent_id).toBe('reviewer')

    const result = await verifyToken(token, { publicKey })
    expect(result.valid).toBe(true)
  })

  it('enforces max_hops', async () => {
    const { wrapper } = await makeWrapper({ max_hops: 2 })
    await wrapper.init()
    await wrapper.onSpeakerTurn('a1', 'msg1')
    await wrapper.onSpeakerTurn('a2', 'msg2')
    await wrapper.onSpeakerTurn('a3', 'msg3') // should be skipped
    expect(wrapper.exportToken()!.chain).toHaveLength(2)
  })

  it('auto-inits on first speaker turn', async () => {
    const { wrapper } = await makeWrapper()
    expect(wrapper.exportToken()).toBeNull()
    await wrapper.onSpeakerTurn('agent', 'hello')
    expect(wrapper.exportToken()).not.toBeNull()
    expect(wrapper.exportToken()!.chain).toHaveLength(1)
  })

  it('allows authorized tool calls', () => {
    const { wrapper } = { wrapper: new HdpAgentWrapper({
      signingKey: new Uint8Array(32),
      sessionId: 's',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', authorized_tools: ['web_search'] },
    })}
    expect(() => wrapper.onToolCall('web_search')).not.toThrow()
  })

  it('rejects strict mode at construction because records cannot gate tool calls', () => {
    expect(() => new HdpAgentWrapper({
      signingKey: new Uint8Array(32),
      sessionId: 's',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', authorized_tools: ['web_search'] },
      strict: true,
    })).toThrow('HDP tokens are records and cannot gate tool calls')
  })

  it('records out-of-scope tool calls and lets the caller proceed', () => {
    const onScopeViolation = vi.fn()
    const wrapper = new HdpAgentWrapper({
      signingKey: new Uint8Array(32),
      sessionId: 's',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', authorized_tools: ['web_search'] },
      onScopeViolation,
    })
    const tool = vi.fn().mockReturnValue('tool ran')

    wrapper.onToolCall('browser_tool')
    const result = tool()

    expect(onScopeViolation).toHaveBeenCalledWith({
      tool: 'browser_tool',
      authorizedTools: ['web_search'],
    })
    expect(result).toBe('tool ran')
    expect(tool).toHaveBeenCalledOnce()
  })

  it('handles rejected scope callbacks without unhandled rejections', async () => {
    const unhandledReasons: unknown[] = []
    const onUnhandledRejection = (reason: unknown) => unhandledReasons.push(reason)
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    process.on('unhandledRejection', onUnhandledRejection)

    try {
      let scopeViolationCalls = 0
      const onScopeViolation = () => {
        scopeViolationCalls++
        return Promise.reject(new Error('scope callback detail'))
      }
      const wrapper = new HdpAgentWrapper({
        signingKey: new Uint8Array(32),
        sessionId: 's',
        principal: { id: 'u', id_type: 'opaque' },
        scope: { intent: 'x', authorized_tools: ['web_search'] },
        onScopeViolation,
      })
      const tool = vi.fn().mockReturnValue('scope tool ran')

      wrapper.onToolCall('browser_tool')
      expect(tool()).toBe('scope tool ran')

      const handler = vi.fn(async (message: AutoGenMessage) => ({ content: message.name }))
      let missingCalls = 0
      let invalidCalls = 0
      let validCalls = 0
      const onMissing = () => {
        missingCalls++
        return Promise.reject(new Error('missing callback detail'))
      }
      const onInvalid = () => {
        invalidCalls++
        return Promise.reject(new Error('invalid callback detail'))
      }
      const onValid = () => {
        validCalls++
        return Promise.reject(new Error('valid callback detail'))
      }

      const missingWrapped = hdpMiddleware(handler, { onMissing })
      expect(await missingWrapped({ name: 'missing' })).toEqual({ content: 'missing' })

      const invalidWrapped = hdpMiddleware(handler, { onInvalid })
      expect(await invalidWrapped({ headers: { 'HDP-Token': 'not-base64url' }, name: 'invalid' }))
        .toEqual({ content: 'invalid' })

      const { token, publicKey } = await makeToken()
      const validWrapped = hdpMiddleware(handler, { verify: { publicKey }, onValid })
      expect(await validWrapped({ headers: { 'HDP-Token': encodeHeader(token) }, name: 'valid' }))
        .toEqual({ content: 'valid' })

      await new Promise<void>(resolve => setImmediate(resolve))

      expect(unhandledReasons).toEqual([])
      expect(scopeViolationCalls).toBe(1)
      expect(missingCalls).toBe(1)
      expect(invalidCalls).toBe(1)
      expect(validCalls).toBe(1)
      expect(tool).toHaveBeenCalledOnce()
      expect(handler).toHaveBeenCalledTimes(3)
      expect(logError.mock.calls).toEqual(expect.arrayContaining([
        ['HDP callback failed: onScopeViolation'],
        ['HDP callback failed: onMissing'],
        ['HDP callback failed: onInvalid'],
        ['HDP callback failed: onValid'],
      ]))
      expect(logError).toHaveBeenCalledTimes(4)
    } finally {
      process.off('unhandledRejection', onUnhandledRejection)
      logError.mockRestore()
    }
  })

  it('continues the tool call after a synchronously throwing onScopeViolation callback', () => {
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = new HdpAgentWrapper({
      signingKey: new Uint8Array(32),
      sessionId: 's',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', authorized_tools: ['web_search'] },
      onScopeViolation: () => { throw new Error('sensitive callback detail') },
    })
    const tool = vi.fn().mockReturnValue('tool result')

    try {
      expect(() => wrapper.onToolCall('browser_tool')).not.toThrow()
      const result = tool()

      expect(result).toBe('tool result')
      expect(tool).toHaveBeenCalledOnce()
      expect(logError.mock.calls).toEqual([['HDP callback failed: onScopeViolation']])
    } finally {
      logError.mockRestore()
    }
  })

  it('allows all tools when authorized_tools is undefined', () => {
    const wrapper = new HdpAgentWrapper({
      signingKey: new Uint8Array(32),
      sessionId: 's',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x' },
    })
    expect(() => wrapper.onToolCall('anything')).not.toThrow()
  })

  it('exports token as JSON string', async () => {
    const { wrapper } = await makeWrapper()
    expect(wrapper.exportTokenJson()).toBeNull()
    await wrapper.init()
    const json = wrapper.exportTokenJson()
    expect(json).not.toBeNull()
    expect(JSON.parse(json!).header.session_id).toBe('sess-autogen-test')
  })
})

// ---------------------------------------------------------------------------
// hdpMiddleware
// ---------------------------------------------------------------------------

describe('hdpMiddleware', () => {
  it('passes through in observe mode when no token is present', async () => {
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    const wrapped = hdpMiddleware(handler)
    const response = await wrapped({ content: 'hello' })
    expect(response).toEqual({ content: 'ok' })
    expect(handler).toHaveBeenCalledOnce()
  })

  it('reports a missing token and still runs the handler', async () => {
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    const onMissing = vi.fn()
    const wrapped = hdpMiddleware(handler, { onMissing })
    const response = await wrapped({ content: 'hello' })
    expect(response).toEqual({ content: 'ok' })
    expect(onMissing).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('rejects the removed required option at construction', () => {
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    expect(() => hdpMiddleware(handler, { hdp_required: true })).toThrow(
      'HDP tokens are records and cannot gate requests',
    )
  })

  it('calls onValid and passes through with a valid token', async () => {
    const { token, publicKey } = await makeToken()
    const encoded = encodeHeader(token)
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onValid,
    })

    const response = await wrapped({
      headers: { 'HDP-Token': encoded, 'X-HDP-Token': 'not-a-token' },
      content: 'hello',
    })
    expect(response).toEqual({ content: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('accepts the deprecated X-prefixed token header as inbound compatibility', async () => {
    const { token, publicKey } = await makeToken()
    const encoded = encodeHeader(token)
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onValid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, content: 'hello' })
    expect(response).toEqual({ content: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('reports an integrity failure and still runs the handler', async () => {
    const { token, publicKey } = await makeToken()
    token.principal.id = 'tampered'
    const encoded = encodeHeader(token)
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onInvalid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, content: 'hello' })
    expect(response).toEqual({ content: 'ok' })
    expect(onInvalid).toHaveBeenCalledWith(expect.objectContaining({
      valid: false,
      failedStep: 2,
      error: expect.any(Error),
    }))
    expect(handler).toHaveBeenCalledOnce()
  })

  it('reports an undecodable token as an input finding and still runs the handler', async () => {
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    const wrapped = hdpMiddleware(handler, { onInvalid })

    const response = await wrapped({ headers: { 'HDP-Token': 'not-base64url' }, content: 'hello' })

    expect(response).toEqual({ content: 'ok' })
    expect(onInvalid).toHaveBeenCalledWith(expect.objectContaining({
      valid: false,
      failedStep: 0,
      error: expect.any(Error),
    }))
    expect(handler).toHaveBeenCalledOnce()
  })

  it.each(['', '   '])('reports an empty token header as an input finding (%j)', async tokenHeader => {
    const onMissing = vi.fn()
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'record-only' })
    const wrapped = hdpMiddleware(handler, { onMissing, onInvalid })

    const response = await wrapped({ headers: { 'HDP-Token': tokenHeader }, content: 'hello' })

    expect(response).toEqual({ content: 'record-only' })
    expect(onInvalid).toHaveBeenCalledWith(expect.objectContaining({
      valid: false,
      failedStep: 0,
      error: expect.any(Error),
    }))
    expect(onMissing).not.toHaveBeenCalled()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('continues the handler after a synchronously throwing onMissing callback', async () => {
    const handler = vi.fn().mockResolvedValue({ content: 'missing' })
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapped = hdpMiddleware(handler, {
      onMissing: () => { throw new Error('sensitive callback detail') },
    })

    try {
      const response = await wrapped({ name: 'missing' })

      expect(response).toEqual({ content: 'missing' })
      expect(handler).toHaveBeenCalledOnce()
      expect(logError.mock.calls).toEqual([['HDP callback failed: onMissing']])
    } finally {
      logError.mockRestore()
    }
  })

  it('continues the handler after a synchronously throwing onInvalid callback', async () => {
    const handler = vi.fn().mockResolvedValue({ content: 'invalid' })
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapped = hdpMiddleware(handler, {
      onInvalid: () => { throw new Error('sensitive callback detail') },
    })

    try {
      const response = await wrapped({
        headers: { 'HDP-Token': 'not-base64url' },
        name: 'invalid',
      })

      expect(response).toEqual({ content: 'invalid' })
      expect(handler).toHaveBeenCalledOnce()
      expect(logError.mock.calls).toEqual([['HDP callback failed: onInvalid']])
    } finally {
      logError.mockRestore()
    }
  })

  it('continues the handler after a synchronously throwing onValid callback', async () => {
    const { token, publicKey } = await makeToken()
    const handler = vi.fn().mockResolvedValue({ content: 'valid' })
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onValid: () => { throw new Error('sensitive callback detail') },
    })

    try {
      const response = await wrapped({
        headers: { 'HDP-Token': encodeHeader(token) },
        name: 'valid',
      })

      expect(response).toEqual({ content: 'valid' })
      expect(handler).toHaveBeenCalledOnce()
      expect(logError.mock.calls).toEqual([['HDP callback failed: onValid']])
    } finally {
      logError.mockRestore()
    }
  })

  it('does not treat an expired record as an integrity failure', async () => {
    const { token, publicKey } = await makeToken(1)
    const onInvalid = vi.fn()
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    const wrapped = hdpMiddleware(handler, { verify: { publicKey }, onInvalid, onValid })

    await new Promise<void>(resolve => setTimeout(
      resolve,
      Math.max(1, token.header.expires_at - Date.now() + 1),
    ))
    expect(token.header.expires_at).toBeLessThan(Date.now())

    const response = await wrapped({ headers: { 'HDP-Token': encodeHeader(token) }, content: 'hello' })

    expect(response).toEqual({ content: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(onInvalid).not.toHaveBeenCalled()
    expect(handler).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// HDP_TOOLS
// ---------------------------------------------------------------------------

describe('HDP_TOOLS', () => {
  it('exports three tool schemas', () => {
    expect(HDP_TOOLS).toHaveLength(3)
    expect(HDP_TOOLS.map(t => t.function.name)).toEqual([
      'hdp_issue_token',
      'hdp_extend_chain',
      'hdp_verify_token',
    ])
  })

  it('getHdpTools returns same tools', () => {
    expect(getHdpTools()).toBe(HDP_TOOLS)
  })
})
