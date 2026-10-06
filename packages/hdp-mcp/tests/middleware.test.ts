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

  it('reports a missing token and still runs the handler', async () => {
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    const onMissing = vi.fn()
    const wrapped = hdpMiddleware(handler, { onMissing })
    const response = await wrapped({ tool: 'my_tool', params: {} })
    expect(response).toEqual({ result: 'ok' })
    expect(onMissing).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('rejects the removed required option at construction', () => {
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    expect(() => hdpMiddleware(handler, { hdp_required: true })).toThrow(
      'HDP tokens are records and cannot gate requests',
    )
  })

  it('calls onValid and passes through with a valid token', async () => {
    const { token, publicKey } = await makeToken()
    const encoded = encodeHeader(token)
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onValid,
    })

    const response = await wrapped({
      headers: { 'HDP-Token': encoded, 'X-HDP-Token': 'not-a-token' },
      tool: 'my_tool',
    })
    expect(response).toEqual({ result: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('accepts the deprecated X-prefixed token header as inbound compatibility', async () => {
    const { token, publicKey } = await makeToken()
    const encoded = encodeHeader(token)
    const onValid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onValid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, tool: 'my_tool' })
    expect(response).toEqual({ result: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('reports an integrity failure and still runs the handler', async () => {
    const { token, publicKey } = await makeToken()
    token.principal.id = 'tampered'
    const encoded = encodeHeader(token)
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })

    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onInvalid,
    })

    const response = await wrapped({ headers: { 'x-hdp-token': encoded }, tool: 'my_tool' })
    expect(response).toEqual({ result: 'ok' })
    expect(onInvalid).toHaveBeenCalledWith(expect.objectContaining({
      valid: false,
      failedStep: 2,
      error: expect.any(Error),
    }))
    expect(handler).toHaveBeenCalledOnce()
  })

  it('reports an undecodable token as an input finding and still runs the handler', async () => {
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    const wrapped = hdpMiddleware(handler, { onInvalid })

    const response = await wrapped({ headers: { 'HDP-Token': 'not-base64url' }, tool: 'my_tool' })

    expect(response).toEqual({ result: 'ok' })
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
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    const wrapped = hdpMiddleware(handler, { verify: { publicKey }, onInvalid, onValid })

    const response = await wrapped({ headers: { 'HDP-Token': encodeHeader(token) }, tool: 'my_tool' })

    expect(response).toEqual({ result: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(onInvalid).not.toHaveBeenCalled()
    expect(handler).toHaveBeenCalledOnce()
  })
})
