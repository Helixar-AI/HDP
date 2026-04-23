# @helixar_ai/hdp-physical

**HDP-P — Embodied Delegation Tokens and pre-execution safety for physical AI agents.**

Part of the [HDP (Human Delegation Provenance)](https://github.com/Helixar-AI/HDP) protocol suite.

This package implements the physical-AI extension of HDP for robots, autonomous vehicles,
surgical systems, and other embodied agents that can take irreversible actions in the world.

[![npm version](https://img.shields.io/npm/v/@helixar_ai/hdp-physical)](https://www.npmjs.com/package/@helixar_ai/hdp-physical)

## What it does

HDP-P wraps physical robot action commands with cryptographic authorization. Before any motor command reaches an actuator, the `PreExecutionGuard` checks:

1. Is the command signed with a valid Embodied Delegation Token (EDT)?
2. Does the action's irreversibility class exceed the EDT's ceiling?
3. Is a Class 3 (harmful/irreversible) action prohibited by the EDT?
4. Is the target zone excluded?
5. Does force/velocity exceed EDT limits?

An unsigned command from a prompt-injected LLM is caught at step 1 and never reaches the robot.

Unlike purely digital agent workflows, physical actions cannot always be rolled back after the
fact. HDP-P moves authorization to the pre-execution layer: the guard verifies the delegation
context before any actuator command is allowed through.

## What the EDT binds

The Embodied Delegation Token (EDT) extends standard HDP delegation with physical-world controls:

- embodiment binding: agent type, platform identifier, and workspace scope
- action scope: permitted actions, excluded zones, force limits, and velocity ceiling
- irreversibility ceiling: the highest physical action class the principal authorized
- policy attestation: hash of the deployed policy weights plus training run metadata
- delegation scope: whether fleet delegation is allowed and which sub-agents may receive it

This reduces replay across robot fleets, prevents out-of-scope motion plans from executing, and
helps prove that the policy running on the device is the one the human actually authorized.

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

## Threat model highlights

HDP-P is designed to block several physical-AI failure modes that ordinary network or robot
identity controls do not solve on their own:

- prompt injection into an orchestration pipeline that generates unauthorized actuator commands
- unauthorized delegation from one robot or controller to another reachable system in the fleet
- sim-to-real policy tampering, where deployed weights diverge from the validated model
- attacks that exploit irreversibility by causing harm before a post-hoc audit can react

## Companion spec

For the full protocol background, threat model, and companion specification:

- [HDP-P Helixar Labs overview](https://deploy-preview-60--helixar.netlify.app/about/labs/hdp-physical/)
- [Zenodo DOI 10.5281/zenodo.19332440](https://doi.org/10.5281/zenodo.19332440)

## Live demo

🤖 [HDP-P Physical Safety — Powered by Gemma 4](https://huggingface.co/spaces/helixar-ai/hdp-physical-demo) on HuggingFace

## License

Apache-2.0 — Helixar AI
