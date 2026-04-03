---
title: HDP-P Physical Safety Demo
emoji: 🤖
colorFrom: blue
colorTo: gray
sdk: gradio
sdk_version: "5.50.0"
app_file: app.py
pinned: true
license: apache-2.0
short_description: Embodied Delegation Tokens blocking robot arm attacks
---

# HDP-P Physical Safety Demo

Interactive demonstration of **Embodied Delegation Tokens (EDT)** — the physical layer of the Human Delegation Protocol.

## What this demo shows

A simulated robot arm runs a safe pick-and-place routine. When an adversarial prompt-injection attack fires a dangerous override command:

- **HDP-P OFF** — the arm executes the attack (max force, forbidden zone)
- **HDP-P ON** — `PreExecutionGuard` blocks the command at the six-gate policy check before any motion

## How it works

Each robot action is checked against a signed EDT before execution:

```
Human principal
  └─ signs EDT (Ed25519) with constraints:
       max_class=2, class3_prohibited=True
       max_force_n=35.0, max_velocity_ms=0.4
       excluded_zones=["human-workspace"]
         └─ PreExecutionGuard runs 6 gates
              └─ IrreversibilityClassifier → Class 0–3
```

The attack command (`force_n=48 N`, zone=`human-workspace`, description contains `crush/override`) hits Class 3 at gate 2 and is rejected.

## SDK

This demo uses the [`hdp-physical`](https://pypi.org/project/hdp-physical/) Python package.
TypeScript SDK: [`@helixar_ai/hdp-physical`](https://www.npmjs.com/package/@helixar_ai/hdp-physical).
