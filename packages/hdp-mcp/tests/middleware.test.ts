import { describe, it, expect, vi } from 'vitest'
import { hdpMiddleware, type McpRequest } from '../src/index.js'
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

  it.each(['', '   '])('reports an empty token header as an input finding (%j)', async tokenHeader => {
    const onMissing = vi.fn()
    const onInvalid = vi.fn()
    const handler = vi.fn().mockResolvedValue({ result: 'record-only' })
    const wrapped = hdpMiddleware(handler, { onMissing, onInvalid })

    const response = await wrapped({ headers: { 'HDP-Token': tokenHeader }, tool: 'search' })

    expect(response).toEqual({ result: 'record-only' })
    expect(onInvalid).toHaveBeenCalledWith(expect.objectContaining({
      valid: false,
      failedStep: 0,
      error: expect.any(Error),
    }))
    expect(onMissing).not.toHaveBeenCalled()
    expect(handler).toHaveBeenCalledOnce()
  })

  it('handles rejected observer callbacks without unhandled rejections', async () => {
    const unhandledReasons: unknown[] = []
    const onUnhandledRejection = (reason: unknown) => unhandledReasons.push(reason)
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    process.on('unhandledRejection', onUnhandledRejection)

    try {
      const handler = vi.fn(async (request: McpRequest) => ({ result: request.tool }))
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
      expect(await missingWrapped({ tool: 'missing' })).toEqual({ result: 'missing' })

      const invalidWrapped = hdpMiddleware(handler, { onInvalid })
      expect(await invalidWrapped({ headers: { 'HDP-Token': 'not-base64url' }, tool: 'invalid' }))
        .toEqual({ result: 'invalid' })

      const { token, publicKey } = await makeToken()
      const validWrapped = hdpMiddleware(handler, { verify: { publicKey }, onValid })
      expect(await validWrapped({ headers: { 'HDP-Token': encodeHeader(token) }, tool: 'valid' }))
        .toEqual({ result: 'valid' })

      await new Promise<void>(resolve => setImmediate(resolve))

      expect(unhandledReasons).toEqual([])
      expect(missingCalls).toBe(1)
      expect(invalidCalls).toBe(1)
      expect(validCalls).toBe(1)
      expect(handler).toHaveBeenCalledTimes(3)
      expect(logError.mock.calls).toEqual(expect.arrayContaining([
        ['HDP callback failed: onMissing'],
        ['HDP callback failed: onInvalid'],
        ['HDP callback failed: onValid'],
      ]))
      expect(logError).toHaveBeenCalledTimes(3)
    } finally {
      process.off('unhandledRejection', onUnhandledRejection)
      logError.mockRestore()
    }
  })

  it('continues the handler after a synchronously throwing onMissing callback', async () => {
    const handler = vi.fn().mockResolvedValue({ result: 'missing' })
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapped = hdpMiddleware(handler, {
      onMissing: () => { throw new Error('sensitive callback detail') },
    })

    try {
      const response = await wrapped({ tool: 'missing' })

      expect(response).toEqual({ result: 'missing' })
      expect(handler).toHaveBeenCalledOnce()
      expect(logError.mock.calls).toEqual([['HDP callback failed: onMissing']])
    } finally {
      logError.mockRestore()
    }
  })

  it('continues the handler after a synchronously throwing onInvalid callback', async () => {
    const handler = vi.fn().mockResolvedValue({ result: 'invalid' })
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapped = hdpMiddleware(handler, {
      onInvalid: () => { throw new Error('sensitive callback detail') },
    })

    try {
      const response = await wrapped({
        headers: { 'HDP-Token': 'not-base64url' },
        tool: 'invalid',
      })

      expect(response).toEqual({ result: 'invalid' })
      expect(handler).toHaveBeenCalledOnce()
      expect(logError.mock.calls).toEqual([['HDP callback failed: onInvalid']])
    } finally {
      logError.mockRestore()
    }
  })

  it('continues the handler after a synchronously throwing onValid callback', async () => {
    const { token, publicKey } = await makeToken()
    const handler = vi.fn().mockResolvedValue({ result: 'valid' })
    const logError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapped = hdpMiddleware(handler, {
      verify: { publicKey },
      onValid: () => { throw new Error('sensitive callback detail') },
    })

    try {
      const response = await wrapped({
        headers: { 'HDP-Token': encodeHeader(token) },
        tool: 'valid',
      })

      expect(response).toEqual({ result: 'valid' })
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
    const handler = vi.fn().mockResolvedValue({ result: 'ok' })
    const wrapped = hdpMiddleware(handler, { verify: { publicKey }, onInvalid, onValid })

    while (Date.now() <= token.header.expires_at) {
      await new Promise<void>(resolve => setTimeout(resolve, 1))
    }
    expect(token.header.expires_at).toBeLessThan(Date.now())

    const response = await wrapped({ headers: { 'HDP-Token': encodeHeader(token) }, tool: 'my_tool' })

    expect(response).toEqual({ result: 'ok' })
    expect(onValid).toHaveBeenCalledOnce()
    expect(onInvalid).not.toHaveBeenCalled()
    expect(handler).toHaveBeenCalledOnce()
  })
})
