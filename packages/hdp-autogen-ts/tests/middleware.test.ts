import { describe, it, expect, vi } from 'vitest'
import { HdpAgentWrapper, hdpMiddleware, HdpScopeViolationError, HDP_TOOLS, getHdpTools } from '../src/index.js'
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

    const result = await verifyToken(token, { publicKey, currentSessionId: 'sess-autogen-test' })
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

  it('throws on unauthorized tool call in strict mode', () => {
    const wrapper = new HdpAgentWrapper({
      signingKey: new Uint8Array(32),
      sessionId: 's',
      principal: { id: 'u', id_type: 'opaque' },
      scope: { intent: 'x', authorized_tools: ['web_search'] },
      strict: true,
    })
    expect(() => wrapper.onToolCall('browser_tool')).toThrow(HdpScopeViolationError)
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

  it('blocks message in required mode when no token is present', async () => {
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })
    const wrapped = hdpMiddleware(handler, { hdp_required: true })
    const response = await wrapped({ content: 'hello' })
    expect((response as any).error).toMatch('HDP_REQUIRED')
    expect(handler).not.toHaveBeenCalled()
  })

  it('calls onValid and passes through with a valid token', async () => {
    const { token, publicKey } = await makeToken()
    const encoded = encodeHeader(token)
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey, currentSessionId: 'sess-autogen-test' },
      hdp_required: true,
      onValid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, content: 'hello' })
    expect(response).toEqual({ content: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('blocks message with an expired token in required mode', async () => {
    const { token, publicKey } = await makeToken(-1000)
    const encoded = encodeHeader(token)
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ content: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey, currentSessionId: 'sess-autogen-test', now: Date.now() + 100 },
      hdp_required: true,
      onInvalid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, content: 'hello' })
    expect((response as any).error).toMatch('HDP_INVALID')
    expect(onInvalid).toHaveBeenCalledOnce()
    expect(handler).not.toHaveBeenCalled()
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
