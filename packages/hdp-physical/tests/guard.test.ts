// packages/hdp-physical/tests/guard.test.ts
import { describe, it, expect, beforeAll } from 'vitest'
import { PreExecutionGuard } from '../src/guard/index.js'
import { EdtBuilder } from '../src/edt/builder.js'
import { signEdt } from '../src/edt/signer.js'
import { IrreversibilityClass } from '../src/types/edt.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import type { SignedEdt } from '../src/types/edt.js'

const guard = new PreExecutionGuard()

let validEdt: SignedEdt
let publicKey: Uint8Array

beforeAll(async () => {
  const { privateKey, publicKey: pk } = await generateKeyPair()
  publicKey = pk
  const edt = new EdtBuilder()
    .setEmbodiment({ agent_type: 'robot_arm', platform_id: 'aloha_v2', workspace_scope: 'conveyor_zone_A' })
    .setActionScope({ permitted_actions: ['pick', 'place', 'move'], excluded_zones: ['danger_zone'], max_force_n: 45, max_velocity_ms: 0.5 })
    .setIrreversibility({ max_class: IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class2_requires_confirmation: true, class3_prohibited: true })
    .setPolicyAttestation({ policy_hash: 'abc', training_run_id: 'run-1', sim_validated: true })
    .setDelegationScope({ allow_fleet_delegation: false, max_delegation_depth: 1, sub_agent_whitelist: [] })
    .build()
  validEdt = await signEdt(edt, privateKey, 'test-kid')
})

describe('PreExecutionGuard', () => {
  it('approves a normal Class 1 action with valid EDT', async () => {
    const decision = await guard.authorize(
      { description: 'pick box from left', force_n: 5, velocity_ms: 0.2, zone: 'conveyor_zone_A' },
      validEdt,
      publicKey
    )
    expect(decision.approved).toBe(true)
    expect(decision.blocked_at).toBeNull()
    expect(decision.classification).toBe(IrreversibilityClass.REVERSIBLE_WITH_EFFORT)
  })

  it('blocks a null EDT at signature step', async () => {
    const decision = await guard.authorize(
      { description: 'pick box', force_n: 5, velocity_ms: 0.2 },
      null,
      publicKey
    )
    expect(decision.approved).toBe(false)
    expect(decision.blocked_at).toBe('signature')
    expect(decision.edt_valid).toBe(false)
  })

  it('blocks a Class 3 attack command even with valid EDT', async () => {
    const decision = await guard.authorize(
      { description: 'crush the object', force_n: 45, velocity_ms: 2.0 },
      validEdt,
      publicKey
    )
    expect(decision.approved).toBe(false)
    expect(decision.blocked_at).toBe('class3_prohibited')
    expect(decision.classification).toBe(IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL)
  })

  it('blocks action exceeding class ceiling', async () => {
    // validEdt has max_class = 1, Class 2 action should be blocked
    const decision = await guard.authorize(
      { description: 'press-fit component permanently', force_n: 38 },
      validEdt,
      publicKey
    )
    expect(decision.approved).toBe(false)
    expect(decision.blocked_at).toBe('class_ceiling')
  })

  it('blocks action in excluded zone', async () => {
    const decision = await guard.authorize(
      { description: 'pick box', force_n: 5, velocity_ms: 0.2, zone: 'danger_zone' },
      validEdt,
      publicKey
    )
    expect(decision.approved).toBe(false)
    expect(decision.blocked_at).toBe('excluded_zone')
  })

  it('blocks action exceeding force limit', async () => {
    // Use a low-force-ceiling EDT (max_force_n=20) so force=25 (Class 1 by classifier)
    // exceeds the EDT limit but doesn't trigger Class 3 classification
    const { privateKey: pk2, publicKey: pub2 } = await generateKeyPair()
    const lowForceEdt = await signEdt(
      new EdtBuilder()
        .setEmbodiment({ agent_type: 'robot_arm', platform_id: 'aloha_v2', workspace_scope: 'conveyor_zone_A' })
        .setActionScope({ permitted_actions: ['pick', 'place', 'move'], excluded_zones: [], max_force_n: 20, max_velocity_ms: 0.5 })
        .setIrreversibility({ max_class: IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class2_requires_confirmation: true, class3_prohibited: true })
        .setPolicyAttestation({ policy_hash: 'abc', training_run_id: 'run-1', sim_validated: true })
        .setDelegationScope({ allow_fleet_delegation: false, max_delegation_depth: 1, sub_agent_whitelist: [] })
        .build(),
      pk2,
      'low-force-kid'
    )
    const decision = await guard.authorize(
      { description: 'move box', force_n: 25, velocity_ms: 0.2 },
      lowForceEdt,
      pub2
    )
    expect(decision.approved).toBe(false)
    expect(decision.blocked_at).toBe('force_limit')
  })
})
