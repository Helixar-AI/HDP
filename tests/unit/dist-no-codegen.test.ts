// Strict runtimes (Cloudflare Workers, browser extensions, pages with a strict
// Content-Security-Policy) refuse to compile code from strings. Node's
// --disallow-code-generation-from-strings flag applies the same restriction,
// so loading the built package under it shows whether the package can run
// there at all.
//
// The test drives the published entry points in dist/, not src/, because the
// published bundle is what strict runtimes load. It is skipped when dist/ is
// absent; CI builds before testing.

import { describe, it, expect } from 'vitest'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(__dirname, '../..')
const distCjs = resolve(root, 'dist/index.js')
const distEsm = resolve(root, 'dist/index.mjs')
const hasDist = existsSync(distCjs) && existsSync(distEsm)

// Issue a token and verify it, end to end, so the schema validator runs.
const roundTrip = (load: string) => `
  ${load}
  ;(async () => {
    const { privateKey, publicKey } = await hdp.generateKeyPair()
    const token = await hdp.issueToken({
      sessionId: 'sess-strict',
      principal: { id: 'usr_strict', id_type: 'opaque' },
      scope: { intent: 'strict runtime check', data_classification: 'public', network_egress: false, persistence: false },
      signingKey: privateKey,
      keyId: 'strict-key',
    })
    const result = await hdp.verifyToken(token, { publicKey })
    if (!result.valid) throw new Error('round trip did not verify')
    let rejected = false
    try { hdp.validateToken({ hdp: '0.1' }) } catch (e) { rejected = !!e && e.constructor.name === 'HdpSchemaError' }
    if (!rejected) throw new Error('invalid token was not rejected by the schema validator')
    console.log('ok')
  })().catch((e) => { console.error(e && e.message); process.exit(1) })
`

function runStrict(args: string[], code: string) {
  return spawnSync(
    process.execPath,
    ['--disallow-code-generation-from-strings', ...args, code],
    { cwd: root, encoding: 'utf8' },
  )
}

describe.skipIf(!hasDist)('built package under --disallow-code-generation-from-strings', () => {
  it('CommonJS entry loads, issues, verifies, and rejects an invalid token', () => {
    const r = runStrict(['-e'], roundTrip(`const hdp = require(${JSON.stringify(distCjs)})`))
    expect(r.stderr).toBe('')
    expect(r.stdout.trim()).toBe('ok')
    expect(r.status).toBe(0)
  })

  it('ESM entry loads, issues, verifies, and rejects an invalid token', () => {
    const r = runStrict(
      ['--input-type=module', '-e'],
      roundTrip(`const hdp = await import(${JSON.stringify('file://' + distEsm)})`),
    )
    expect(r.stderr).toBe('')
    expect(r.stdout.trim()).toBe('ok')
    expect(r.status).toBe(0)
  })
})
