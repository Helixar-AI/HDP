import { describe, it, expect } from 'vitest'
import { generateKeyPair, issueToken, extendChain } from '@helixar/hdp'
import { execSync } from 'child_process'
import { writeFileSync, unlinkSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

async function makeValidToken() {
  const { privateKey } = await generateKeyPair()
  let token = await issueToken({
    sessionId: 'sess-cli-test',
    principal: { id: 'u', id_type: 'opaque' },
    scope: { intent: 'cli test', data_classification: 'public', network_egress: false, persistence: false },
    signingKey: privateKey, keyId: 'k1',
  })
  token = await extendChain(token, { agent_id: 'a1', agent_type: 'orchestrator', action_summary: 'test hop', parent_hop: 0 }, privateKey)
  return token
}

function runCli(input: string): { stdout: string; stderr: string; exitCode: number } {
  const tmp = join(tmpdir(), `hdp-test-${Date.now()}.json`)
  writeFileSync(tmp, input)
  try {
    const stdout = execSync(`node dist/cli.js ${tmp}`, {
      cwd: join(import.meta.dirname, '..'),
      encoding: 'utf8',
    })
    unlinkSync(tmp)
    return { stdout, stderr: '', exitCode: 0 }
  } catch (e: any) {
    unlinkSync(tmp)
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', exitCode: e.status ?? 1 }
  }
}

describe('hdp-validate CLI', () => {
  it('exits 0 and prints VALID for a well-formed token', async () => {
    const token = await makeValidToken()
    const { stdout, exitCode } = runCli(JSON.stringify(token))
    expect(exitCode).toBe(0)
    expect(stdout).toContain('✓ VALID')
    expect(stdout).toContain(token.header.token_id)
  })

  it('exits 1 for invalid JSON', () => {
    const { exitCode, stderr } = runCli('not json at all')
    expect(exitCode).toBe(1)
    expect(stderr).toContain('INVALID')
  })

  it('exits 1 for a token missing required schema fields', () => {
    const { exitCode, stderr } = runCli(JSON.stringify({ hdp: '0.1' }))
    expect(exitCode).toBe(1)
    expect(stderr).toContain('INVALID')
  })
})
