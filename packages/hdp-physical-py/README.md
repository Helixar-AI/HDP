# hdp-physical

**HDP-P — Embodied Delegation Tokens and pre-execution safety for physical AI agents.**

Part of the [HDP (Human Delegation Provenance)](https://github.com/Helixar-AI/HDP) protocol suite.

[![PyPI version](https://img.shields.io/pypi/v/hdp-physical)](https://pypi.org/project/hdp-physical/)

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
pip install hdp-physical
```

Optional extras:

```bash
pip install "hdp-physical[lerobot]"   # LeRobot adapter
pip install "hdp-physical[gemma]"     # Gemma interceptor
```

## Quick start

```python
import asyncio
from hdp_physical import (
    EdtBuilder, sign_edt, PreExecutionGuard, IrreversibilityClass
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

async def main():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    edt = (
        EdtBuilder()
        .set_embodiment(agent_type="robot_arm", platform_id="aloha_v2", workspace_scope="zone_A")
        .set_action_scope(permitted_actions=["pick", "place", "move"], excluded_zones=[], max_force_n=45, max_velocity_ms=0.5)
        .set_irreversibility(max_class=IrreversibilityClass.REVERSIBLE_WITH_EFFORT, class2_requires_confirmation=True, class3_prohibited=True)
        .set_policy_attestation(policy_hash="sha256-of-weights", training_run_id="run-1", sim_validated=True)
        .set_delegation_scope(allow_fleet_delegation=False, max_delegation_depth=1, sub_agent_whitelist=[])
        .build()
    )

    signed_edt = await sign_edt(edt, private_key, "my-key")
    guard = PreExecutionGuard()

    decision = await guard.authorize(
        {"description": "pick box from left", "force_n": 5, "velocity_ms": 0.2},
        signed_edt,
        public_key,
    )

    if decision.approved:
        print("✅ Action approved — safe to send to actuator")
    else:
        print(f"🛑 Blocked at: {decision.blocked_at} — {decision.reason}")

asyncio.run(main())
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

Apache-2.0 — Helixar AI
