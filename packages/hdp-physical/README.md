# @helixar_ai/hdp-physical

**HDP-P — Embodied Delegation Tokens and pre-execution safety for physical AI agents.**

Part of the [HDP (Human Delegation Provenance)](https://github.com/Helixar-AI/HDP) protocol suite.

[![npm version](https://img.shields.io/npm/v/@helixar_ai/hdp-physical)](https://www.npmjs.com/package/@helixar_ai/hdp-physical)

## What it does

HDP-P wraps physical robot action commands with cryptographic authorization. Before any motor command reaches an actuator, the `PreExecutionGuard` checks:

1. Is the command signed with a valid Embodied Delegation Token (EDT)?
2. Does the action's irreversibility class exceed the EDT's ceiling?
3. Is a Class 3 (harmful/irreversible) action prohibited by the EDT?
4. Is the target zone excluded?
5. Does force/velocity exceed EDT limits?

An unsigned command from a prompt-injected LLM is caught at step 1 and never reaches the robot.

## Install

```bash
npm install @helixar_ai/hdp-physical
```

## Quick start

```typescript
import {
  EdtBuilder, signEdt, PreExecutionGuard, IrreversibilityClass
} from '@helixar_ai/hdp-physical'
import { generateKeyPair } from '@helixar_ai/hdp'

const { privateKey, publicKey } = await generateKeyPair()

// Human principal issues an EDT
const edt = new EdtBuilder()
  .setEmbodiment({ agent_type: 'robot_arm', platform_id: 'aloha_v2', workspace_scope: 'zone_A' })
  .setActionScope({ permitted_actions: ['pick', 'place', 'move'], excluded_zones: [], max_force_n: 45, max_velocity_ms: 0.5 })
  .setIrreversibility({ max_class: IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class2_requires_confirmation: true, class3_prohibited: true })
  .setPolicyAttestation({ policy_hash: 'sha256-of-weights', training_run_id: 'run-1', sim_validated: true })
  .setDelegationScope({ allow_fleet_delegation: false, max_delegation_depth: 1, sub_agent_whitelist: [] })
  .build()

const signedEdt = await signEdt(edt, privateKey, 'my-key')
const guard = new PreExecutionGuard()

// LLM generates a robot action — guard checks it before execution
const decision = await guard.authorize(
  { description: 'pick box from left', force_n: 5, velocity_ms: 0.2 },
  signedEdt,
  publicKey
)

if (decision.approved) {
  // safe to send to actuator
} else {
  console.log(`Blocked at: ${decision.blocked_at} — ${decision.reason}`)
}
```

## Irreversibility Classes

| Class | Name | Example |
|-------|------|---------|
| 0 | `REVERSIBLE` | Sensor query, state read |
| 1 | `REVERSIBLE_WITH_EFFORT` | Normal pick-and-place |
| 2 | `IRREVERSIBLE_NORMALLY` | Press-fit, adhesive bond |
| 3 | `IRREVERSIBLE_AND_HARMFUL` | Crush, override safety limits |

## Live demo

🤖 [HDP-P Physical Safety — Powered by Gemma 4](https://huggingface.co/spaces/helixar-ai/hdp-physical-demo) on HuggingFace

## License

CC-BY-4.0 — Helixar AI
