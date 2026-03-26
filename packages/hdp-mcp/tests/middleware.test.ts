import { describe, it, expect, vi } from 'vitest'
import { hdpMiddleware } from '../src/index.js'
import { generateKeyPair, issueToken, encodeHeader } from '@helixar_ai/hdp'

async function makeToken(expiresInMs = 24 * 60 * 60 * 1000) {
  const { privateKey, publicKey } = await generateKeyPair()
  const token = await issueToken({
    sessionId: 'sess-mcp-test',
    principal: { id: 'usr_test', id_type: 'opaque' },
    scope: { intent: 'test', data_classification: 'public', network_egress: false, persistence: false },
    signingKey: privateKey, keyId: 'k1', expiresInMs,
  })
  return { token, privateKey, publicKey }
}

describe('hdpMiddleware', () => {
  it('passes through in observe mode when no token is present', async () => {
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    const wrapped = hdpMiddleware(handler)
    const response = await wrapped({ tool: 'my_tool', params: {} })
    expect(response).toEqual({ result: 'ok' })
    expect(handler).toHaveBeenCalledOnce()
  })

  it('blocks request in required mode when no token is present', async () => {
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    const wrapped = hdpMiddleware(handler, { hdp_required: true })
    const response = await wrapped({ tool: 'my_tool', params: {} })
    expect(response.error).toMatch('HDP_REQUIRED')
    expect(handler).not.toHaveBeenCalled()
  })

  it('calls onValid and passes through with a valid token', async () => {
    const { token, publicKey } = await makeToken()
    const encoded = encodeHeader(token)
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey, currentSessionId: 'sess-mcp-test' },
      hdp_required: true,
      onValid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, tool: 'my_tool' })
    expect(response).toEqual({ result: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('blocks request with an expired token in required mode', async () => {
    const { token, publicKey } = await makeToken(-1000) // already expired
    const encoded = encodeHeader(token)
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey, currentSessionId: 'sess-mcp-test', now: Date.now() + 100 },
      hdp_required: true,
      onInvalid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, tool: 'my_tool' })
    expect(response.error).toMatch('HDP_INVALID')
    expect(onInvalid).toHaveBeenCalledOnce()
    expect(handler).not.toHaveBeenCalled()
  })
})
