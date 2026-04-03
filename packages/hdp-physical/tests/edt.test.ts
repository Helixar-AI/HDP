// packages/hdp-physical/tests/edt.test.ts
import { describe, it, expect } from 'vitest'
import { signEdt } from '../src/edt/signer.js'
import { verifyEdt } from '../src/edt/verifier.js'
import { EdtBuilder } from '../src/edt/builder.js'
import { edtToHdpExtension, edtFromHdpExtension } from '../src/edt/bridge.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { IrreversibilityClass } from '../src/types/edt.js'
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

describe('EdtBuilder', () => {
  it('builds a valid EdtToken via fluent API', () => {
    const edt = new EdtBuilder()
      .setEmbodiment({ agent_type: 'robot_arm', platform_id: 'aloha_v2', workspace_scope: 'zone_A' })
      .setActionScope({ permitted_actions: ['pick', 'place'], excluded_zones: [], max_force_n: 45, max_velocity_ms: 0.5 })
      .setIrreversibility({ max_class: IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class2_requires_confirmation: true, class3_prohibited: true })
      .setPolicyAttestation({ policy_hash: 'abc123', training_run_id: 'run-1', sim_validated: true })
      .setDelegationScope({ allow_fleet_delegation: false, max_delegation_depth: 1, sub_agent_whitelist: [] })
      .build()
    expect(edt.embodiment.agent_type).toBe('robot_arm')
    expect(edt.irreversibility.max_class).toBe(1)
  })

  it('throws if required fields are missing', () => {
    const builder = new EdtBuilder()
    expect(() => builder.build()).toThrow('EdtBuilder: embodiment is required')
  })
})

describe('edtToHdpExtension', () => {
  it('wraps a SignedEdt into an hdp-p extensions object', async () => {
    const { privateKey } = await generateKeyPair()
    const signed = await signEdt(SAMPLE_EDT, privateKey, 'test-kid')
    const ext = edtToHdpExtension(signed)
    expect(ext['hdp-p']).toBeDefined()
    expect((ext['hdp-p'] as Record<string, unknown>).edt).toEqual(SAMPLE_EDT)
    expect((ext['hdp-p'] as Record<string, unknown>).signature).toBe(signed.signature)
  })

  it('round-trips through edtFromHdpExtension', async () => {
    const { privateKey } = await generateKeyPair()
    const signed = await signEdt(SAMPLE_EDT, privateKey, 'test-kid')
    const ext = edtToHdpExtension(signed)
    const recovered = edtFromHdpExtension(ext)
    expect(recovered).not.toBeNull()
    expect(recovered!.kid).toBe('test-kid')
    expect(recovered!.alg).toBe('Ed25519')
  })

  it('returns null for missing or malformed extensions', () => {
    expect(edtFromHdpExtension(undefined)).toBeNull()
    expect(edtFromHdpExtension({})).toBeNull()
    expect(edtFromHdpExtension({ 'hdp-p': 'not-an-object' })).toBeNull()
  })
})
