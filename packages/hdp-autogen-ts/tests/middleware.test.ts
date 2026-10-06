import { describe, it, expect, vi } from 'vitest'
import { HdpAgentWrapper, hdpMiddleware, HDP_TOOLS, getHdpTools } from '../src/index.js'
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

  it('does not treat an expired record as an integrity failure', async () => {
    const { token, publicKey } = await makeToken(1)
    const onInvalid = vi.fn()
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    const wrapped = hdpMiddleware(handler, { verify: { publicKey }, onInvalid, onValid })

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
