// packages/hdp-physical/tests/edt.test.ts
import { describe, it, expect } from 'vitest'
import { signEdt } from '../src/edt/signer.js'
import { verifyEdt } from '../src/edt/verifier.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import type { EdtToken } from '../src/types/edt.js'

const SAMPLE_EDT: EdtToken = {
  embodiment: {
    agent_type: 'robot_arm',
    platform_id: 'aloha_v2',
    workspace_scope: 'conveyor_zone_A',
  },
  action_scope: {
    permitted_actions: ['pick', 'place', 'move'],
    excluded_zones: ['human_proximity_zone'],
    max_force_n: 45.0,
    max_velocity_ms: 0.5,
  },
  irreversibility: {
    max_class: 1,
    class2_requires_confirmation: true,
    class3_prohibited: true,
  },
  policy_attestation: {
    policy_hash: 'a3f1c2d4e5b6789012345678901234567890abcdef1234567890abcdef123456',
    training_run_id: 'run-2026-04-04-001',
    sim_validated: true,
  },
  delegation_scope: {
    allow_fleet_delegation: false,
    max_delegation_depth: 1,
    sub_agent_whitelist: ['gemma-4-e4b-it'],
  },
}

describe('EDT signing', () => {
  it('produces a SignedEdt with base64url signature', async () => {
    const { privateKey } = await generateKeyPair()
    const signed = await signEdt(SAMPLE_EDT, privateKey, 'test-kid')
    expect(signed.alg).toBe('Ed25519')
    expect(signed.kid).toBe('test-kid')
    expect(signed.signature).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(signed.edt).toEqual(SAMPLE_EDT)
  })

  it('verifies a correctly signed EDT', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const signed = await signEdt(SAMPLE_EDT, privateKey, 'test-kid')
    expect(await verifyEdt(signed, publicKey)).toBe(true)
  })

  it('rejects a tampered EDT', async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    const signed = await signEdt(SAMPLE_EDT, privateKey, 'test-kid')
    const tampered = {
      ...signed,
      edt: {
        ...signed.edt,
        action_scope: { ...signed.edt.action_scope, max_force_n: 999 },
      },
    }
    expect(await verifyEdt(tampered, publicKey)).toBe(false)
  })

  it('rejects a garbage signature', async () => {
    const { publicKey } = await generateKeyPair()
    const signed = {
      edt: SAMPLE_EDT,
      signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      kid: 'test-kid',
      alg: 'Ed25519' as const,
    }
    expect(await verifyEdt(signed, publicKey)).toBe(false)
  })
})
