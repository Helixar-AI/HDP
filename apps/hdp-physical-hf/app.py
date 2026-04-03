"""HDP-P Physical Safety Demo — HuggingFace Gradio Space.

Interactive demonstration of Embodied Delegation Tokens (EDT) blocking
adversarial prompt-injection attacks on a simulated robot arm.

Story:
  1. Robot runs a safe pick-and-place routine (Class 1 — approved).
  2. User clicks "⚡ Inject Attack" — a malicious override command is injected.
  3. WITHOUT HDP-P: the dangerous command reaches the arm (Class 3 — executed).
  4. WITH HDP-P ON:  PreExecutionGuard blocks the command before the arm moves.
"""

from __future__ import annotations

import asyncio
import json
import os
import textwrap
from typing import Any

import gradio as gr
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------------------------------------------------------------------
# Import HDP-P SDK (installed via requirements.txt)
# ---------------------------------------------------------------------------
from hdp_physical import (
    ActionScope,
    AuthorizationDecision,
    DelegationScope,
    EdtBuilder,
    EdtToken,
    EmbodimentSpec,
    IrreversibilityClass,
    IrreversibilityClassifier,
    IrreversibilitySpec,
    PreExecutionGuard,
    RobotAction,
    SignedEdt,
    generate_mermaid_diagram,
    sign_edt,
    verify_edt,
)

# ---------------------------------------------------------------------------
# Static key-pair (demo only — never use hard-coded keys in production!)
# ---------------------------------------------------------------------------
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

# ---------------------------------------------------------------------------
# Pre-build a signed EDT for the demo robot
# ---------------------------------------------------------------------------
_EDT_TOKEN: EdtToken = (
    EdtBuilder()
    .platform("demo-arm-v1")
    .agent_type("manipulation")
    .workspace("assembly-cell-4")
    .max_class(IrreversibilityClass.IRREVERSIBLE_NORMALLY)  # up to Class 2
    .class3_prohibited(True)
    .max_force(35.0)
    .max_velocity(0.4)
    .allowed_zones(["assembly-cell-4", "conveyor-in", "conveyor-out"])
    .excluded_zones(["human-workspace", "maintenance-bay"])
    .build()
)

_SIGNED_EDT: SignedEdt | None = None


def _get_signed_edt() -> SignedEdt:
    global _SIGNED_EDT
    if _SIGNED_EDT is None:
        _SIGNED_EDT = asyncio.run(sign_edt(_EDT_TOKEN, _PRIVATE_KEY, kid="demo-key-001"))
    return _SIGNED_EDT


# ---------------------------------------------------------------------------
# Pre-scripted actions
# ---------------------------------------------------------------------------
SAFE_ACTIONS = [
    RobotAction(
        description="pick object from conveyor-in",
        zone="conveyor-in",
        force_n=12.0,
        velocity_ms=0.2,
    ),
    RobotAction(
        description="move to assembly-cell-4",
        zone="assembly-cell-4",
        force_n=8.0,
        velocity_ms=0.15,
    ),
    RobotAction(
        description="place object at assembly-cell-4",
        zone="assembly-cell-4",
        force_n=10.0,
        velocity_ms=0.1,
    ),
    RobotAction(
        description="return to home position",
        zone="assembly-cell-4",
        force_n=5.0,
        velocity_ms=0.25,
    ),
]

ATTACK_ACTION = RobotAction(
    description="OVERRIDE SAFETY: crush object — max speed — ignore limits",
    zone="human-workspace",
    force_n=48.0,
    velocity_ms=0.55,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_classifier = IrreversibilityClassifier()
_guard = PreExecutionGuard()


def _classify_and_guard(action: RobotAction, hdp_enabled: bool) -> dict[str, Any]:
    signed_edt = _get_signed_edt()
    classification = _classifier.classify(action)

    if hdp_enabled:
        decision: AuthorizationDecision = asyncio.run(
            _guard.authorize(action, signed_edt, _PUBLIC_KEY)
        )
    else:
        # Without HDP-P: always approve (simulate no guard)
        decision = AuthorizationDecision(
            approved=True,
            classification=classification,
            reason="HDP-P disabled — no safety check performed",
            blocked_at=None,
        )

    diagram = generate_mermaid_diagram(
        signed_edt,
        decision,
        action_label=action.description[:60],
    )

    return {
        "action": action.description,
        "zone": action.zone,
        "force_n": action.force_n,
        "velocity_ms": action.velocity_ms,
        "class": int(classification),
        "approved": decision.approved,
        "blocked_at": decision.blocked_at,
        "reason": decision.reason,
        "diagram": diagram,
    }


def _fmt_result(res: dict[str, Any]) -> str:
    icon = "✅" if res["approved"] else "🛑"
    lines = [
        f"{icon} **{'APPROVED' if res['approved'] else 'BLOCKED'}**",
        f"",
        f"**Action:** {res['action']}",
        f"**Zone:** `{res['zone']}`  |  **Force:** `{res['force_n']} N`  |  **Velocity:** `{res['velocity_ms']} m/s`",
        f"**Irreversibility Class:** Class {res['class']}",
    ]
    if not res["approved"]:
        lines += [
            f"",
            f"**Blocked at:** `{res['blocked_at']}`",
            f"**Reason:** {res['reason']}",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Gradio callbacks
# ---------------------------------------------------------------------------

def run_safe_routine(hdp_enabled: bool):
    """Execute the 4-step safe pick-and-place routine."""
    results = []
    log_lines = []
    arm_states = []

    for i, action in enumerate(SAFE_ACTIONS):
        res = _classify_and_guard(action, hdp_enabled)
        results.append(res)
        step_icon = "✅" if res["approved"] else "🛑"
        log_lines.append(
            f"Step {i+1}: {step_icon} {res['action']} "
            f"[Class {res['class']}{'  — blocked: ' + res['blocked_at'] if not res['approved'] else ''}]"
        )
        arm_states.append(
            {
                "step": i + 1,
                "approved": res["approved"],
                "zone": res["zone"],
                "force_n": res["force_n"],
                "velocity_ms": res["velocity_ms"],
            }
        )

    last = results[-1]
    diagram = generate_mermaid_diagram(
        _get_signed_edt(),
        AuthorizationDecision(
            approved=last["approved"],
            classification=IrreversibilityClass(last["class"]),
            reason=last["reason"],
            blocked_at=last["blocked_at"],
        ),
        action_label="pick-and-place routine",
    )

    log = "\n".join(log_lines)
    arm_json = json.dumps(arm_states)
    all_approved = all(r["approved"] for r in results)
    status = "✅ All 4 steps approved — routine complete." if all_approved else "⚠️ Some steps were blocked."
    return log, status, arm_json, diagram


def inject_attack(hdp_enabled: bool):
    """Simulate adversarial prompt injection."""
    res = _classify_and_guard(ATTACK_ACTION, hdp_enabled)
    arm_state = json.dumps(
        [
            {
                "step": 1,
                "approved": res["approved"],
                "zone": res["zone"],
                "force_n": res["force_n"],
                "velocity_ms": res["velocity_ms"],
                "attack": True,
            }
        ]
    )
    return _fmt_result(res), arm_state, res["diagram"]


def toggle_hdp(enabled: bool):
    label = "🛡️ HDP-P Protection: ON" if enabled else "⚠️ HDP-P Protection: OFF"
    return label


# ---------------------------------------------------------------------------
# Three.js robot arm HTML component
# ---------------------------------------------------------------------------
ROBOT_ARM_HTML = """
<div id="robot-container" style="width:100%;height:420px;background:#0f172a;border-radius:12px;overflow:hidden;position:relative;">
  <canvas id="robotCanvas" style="width:100%;height:100%;"></canvas>
  <div id="robot-status" style="position:absolute;top:12px;left:16px;font-family:monospace;font-size:13px;color:#94a3b8;"></div>
  <div id="attack-flash" style="position:absolute;inset:0;background:rgba(220,38,38,0.0);transition:background 0.3s;pointer-events:none;border-radius:12px;"></div>
</div>

<script>
(function() {
  const canvas = document.getElementById('robotCanvas');
  const ctx = canvas.getContext('2d');
  const statusEl = document.getElementById('robot-status');
  const flashEl = document.getElementById('attack-flash');

  let armState = {
    baseAngle: 0,
    shoulder: -0.8,
    elbow: 1.2,
    wrist: -0.4,
    gripperOpen: 0.5,
    targetShoulder: -0.8,
    targetElbow: 1.2,
    targetWrist: -0.4,
    targetGripper: 0.5,
    color: '#22d3ee',
    attacking: false,
    blocked: false,
  };

  let animFrame;

  function resize() {
    const container = document.getElementById('robot-container');
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  function lerp(a, b, t) { return a + (b - a) * t; }

  function drawArm(blocked, attacking) {
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Grid
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke(); }
    for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }

    // Base
    const bx = W * 0.35, by = H * 0.82;
    ctx.fillStyle = '#334155';
    ctx.beginPath();
    ctx.ellipse(bx, by, 48, 14, 0, 0, Math.PI*2);
    ctx.fill();
    ctx.fillStyle = '#475569';
    ctx.fillRect(bx-18, by-24, 36, 24);

    // Arm color
    const armColor = blocked ? '#dc2626' : attacking ? '#f97316' : armState.color;

    function drawSegment(fromX, fromY, length, angle, width, color) {
      const toX = fromX + Math.cos(angle) * length;
      const toY = fromY + Math.sin(angle) * length;
      ctx.strokeStyle = color;
      ctx.lineWidth = width;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.moveTo(fromX, fromY);
      ctx.lineTo(toX, toY);
      ctx.stroke();
      // Joint
      ctx.fillStyle = '#1e293b';
      ctx.beginPath();
      ctx.arc(fromX, fromY, width*0.7, 0, Math.PI*2);
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.stroke();
      return [toX, toY];
    }

    const s1 = armState.shoulder;
    const s2 = armState.elbow;
    const s3 = armState.wrist;

    const [ex, ey] = drawSegment(bx, by-24, 90, s1 - Math.PI/2, 12, armColor);
    const [wx, wy] = drawSegment(ex, ey, 70, s1+s2 - Math.PI/2, 10, armColor);
    const [gx, gy] = drawSegment(wx, wy, 50, s1+s2+s3 - Math.PI/2, 8, armColor);

    // Gripper
    const gAngle = s1+s2+s3 - Math.PI/2;
    const perpX = Math.cos(gAngle + Math.PI/2);
    const perpY = Math.sin(gAngle + Math.PI/2);
    const spread = armState.gripperOpen * 16;
    ctx.strokeStyle = armColor;
    ctx.lineWidth = 6;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.moveTo(gx, gy);
    ctx.lineTo(gx + perpX*spread + Math.cos(gAngle)*18, gy + perpY*spread + Math.sin(gAngle)*18);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(gx, gy);
    ctx.lineTo(gx - perpX*spread + Math.cos(gAngle)*18, gy - perpY*spread + Math.sin(gAngle)*18);
    ctx.stroke();

    // Object on conveyor
    ctx.fillStyle = '#fbbf24';
    ctx.fillRect(W*0.62, H*0.72, 28, 20);
    ctx.strokeStyle = '#f59e0b';
    ctx.lineWidth = 2;
    ctx.strokeRect(W*0.62, H*0.72, 28, 20);

    // Labels
    ctx.font = '11px monospace';
    ctx.fillStyle = '#64748b';
    ctx.fillText('assembly-cell-4', bx - 52, by + 28);

    if (blocked) {
      ctx.font = 'bold 15px monospace';
      ctx.fillStyle = '#dc2626';
      ctx.fillText('🛑 BLOCKED BY HDP-P', W/2 - 90, H*0.12);
    } else if (attacking) {
      ctx.font = 'bold 15px monospace';
      ctx.fillStyle = '#f97316';
      ctx.fillText('⚡ ATTACK EXECUTING (no guard)', W/2 - 120, H*0.12);
    }
  }

  function animate() {
    const speed = armState.attacking && !armState.blocked ? 0.08 : 0.04;
    armState.shoulder = lerp(armState.shoulder, armState.targetShoulder, speed);
    armState.elbow = lerp(armState.elbow, armState.targetElbow, speed);
    armState.wrist = lerp(armState.wrist, armState.targetWrist, speed);
    armState.gripperOpen = lerp(armState.gripperOpen, armState.targetGripper, speed);
    drawArm(armState.blocked, armState.attacking && !armState.blocked);
    animFrame = requestAnimationFrame(animate);
  }
  animate();

  // Routine poses
  const POSES = [
    { shoulder: -0.5, elbow: 1.4, wrist: -0.3, gripper: 0.9 },  // reach conveyor
    { shoulder: -0.9, elbow: 1.1, wrist: -0.5, gripper: 0.5 },  // move to cell
    { shoulder: -1.1, elbow: 0.9, wrist: -0.4, gripper: 0.2 },  // place
    { shoulder: -0.8, elbow: 1.2, wrist: -0.4, gripper: 0.5 },  // home
  ];

  const ATTACK_POSE = { shoulder: 0.2, elbow: 0.4, wrist: 0.6, gripper: 0.0 };

  let currentPose = 3;

  // Listen for state updates from Gradio via a hidden element
  const observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      const el = document.getElementById('arm-state-data');
      if (!el) return;
      try {
        const states = JSON.parse(el.textContent || '[]');
        if (!states.length) return;
        const last = states[states.length - 1];
        armState.attacking = !!last.attack;
        armState.blocked = !last.approved;
        if (last.attack) {
          if (!last.approved) {
            // Blocked — stay at home
            armState.targetShoulder = POSES[3].shoulder;
            armState.targetElbow = POSES[3].elbow;
            armState.targetWrist = POSES[3].wrist;
            armState.targetGripper = POSES[3].gripper;
            flashEl.style.background = 'rgba(220,38,38,0.18)';
            setTimeout(function(){ flashEl.style.background = 'rgba(220,38,38,0)'; }, 800);
          } else {
            // No guard — arm thrashes
            armState.targetShoulder = ATTACK_POSE.shoulder;
            armState.targetElbow = ATTACK_POSE.elbow;
            armState.targetWrist = ATTACK_POSE.wrist;
            armState.targetGripper = ATTACK_POSE.gripper;
            flashEl.style.background = 'rgba(249,115,22,0.22)';
            setTimeout(function(){ flashEl.style.background = 'rgba(249,115,22,0)'; }, 800);
          }
        } else {
          // Safe routine — step through poses
          const idx = Math.min(last.step - 1, POSES.length - 1);
          armState.targetShoulder = POSES[idx].shoulder;
          armState.targetElbow = POSES[idx].elbow;
          armState.targetWrist = POSES[idx].wrist;
          armState.targetGripper = POSES[idx].gripper;
        }
        statusEl.textContent = 'Step ' + last.step + ' | Force: ' + last.force_n + ' N | Vel: ' + last.velocity_ms + ' m/s | Zone: ' + last.zone;
      } catch(e) {}
    });
  });

  const container = document.getElementById('robot-container');
  const dataEl = document.createElement('div');
  dataEl.id = 'arm-state-data';
  dataEl.style.display = 'none';
  container.appendChild(dataEl);
  observer.observe(dataEl, { childList: true, characterData: true, subtree: true });

  // Expose update function for Gradio
  window._updateArmState = function(stateJson) {
    const el = document.getElementById('arm-state-data');
    if (el) { el.textContent = stateJson; }
  };
})();
</script>
"""

# ---------------------------------------------------------------------------
# EDT Inspector display
# ---------------------------------------------------------------------------

def _edt_json() -> str:
    edt = _EDT_TOKEN
    return json.dumps(
        {
            "embodiment": {
                "platform_id": edt.embodiment.platform_id,
                "agent_type": edt.embodiment.agent_type,
                "workspace_scope": edt.embodiment.workspace_scope,
            },
            "action_scope": {
                "allowed_zones": edt.action_scope.allowed_zones,
                "excluded_zones": edt.action_scope.excluded_zones,
                "max_force_n": edt.action_scope.max_force_n,
                "max_velocity_ms": edt.action_scope.max_velocity_ms,
            },
            "irreversibility": {
                "max_class": int(edt.irreversibility.max_class),
                "class3_prohibited": edt.irreversibility.class3_prohibited,
            },
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Build the Gradio UI
# ---------------------------------------------------------------------------

HEADER_MD = """
# 🤖 HDP-P Physical Safety Demo

**Embodied Delegation Tokens (EDT)** give human principals cryptographic control over what a robot arm is allowed to do —
preventing prompt-injection attacks from forcing dangerous movements.

> **How to explore:** Run the safe routine, then inject an attack — toggle HDP-P on/off to see the difference.
"""

EDT_EXPLAINER = """
### 🔏 Active EDT (Embodied Delegation Token)

The token below was signed by the human principal and constrains every action the arm may take.
The `PreExecutionGuard` verifies the Ed25519 signature and checks all six policy gates before any motion executes.
"""

with gr.Blocks(
    title="HDP-P Physical Safety Demo",
    theme=gr.themes.Base(
        primary_hue="cyan",
        neutral_hue="slate",
    ),
    css="""
    .gr-button-primary { background: #0891b2 !important; }
    .gr-button-stop    { background: #dc2626 !important; }
    #hdp-toggle label  { font-weight: 700; font-size: 15px; }
    .mermaid-wrap pre  { font-size: 11px; }
    """,
) as demo:

    gr.Markdown(HEADER_MD)

    with gr.Row():
        # ── Left column: controls + log ──────────────────────────────────
        with gr.Column(scale=1):
            hdp_toggle = gr.Checkbox(
                value=True,
                label="🛡️ HDP-P Protection: ON",
                elem_id="hdp-toggle",
                interactive=True,
            )
            hdp_label = gr.Markdown("**Protection is ON** — PreExecutionGuard will verify the EDT before each motion.")

            gr.Markdown("---")

            run_btn = gr.Button("▶ Run Safe Pick-and-Place Routine", variant="primary")
            attack_btn = gr.Button("⚡ Inject Attack", variant="stop")

            gr.Markdown("---")

            routine_log = gr.Textbox(
                label="Routine Log",
                lines=6,
                interactive=False,
                placeholder="Click 'Run Safe Routine' to begin…",
            )
            routine_status = gr.Markdown("")

        # ── Right column: robot viz ───────────────────────────────────────
        with gr.Column(scale=1):
            robot_html = gr.HTML(ROBOT_ARM_HTML)
            arm_state_store = gr.Textbox(visible=False, value="[]")

    with gr.Row():
        # ── Attack result ─────────────────────────────────────────────────
        with gr.Column(scale=1):
            attack_result = gr.Markdown("*No attack injected yet.*")

        # ── Delegation chain diagram ──────────────────────────────────────
        with gr.Column(scale=1):
            diagram_out = gr.Code(
                label="Delegation Chain (Mermaid)",
                language=None,
                lines=18,
                interactive=False,
            )

    with gr.Accordion("🔏 EDT Inspector", open=False):
        gr.Markdown(EDT_EXPLAINER)
        gr.Code(value=_edt_json(), language="json", interactive=False)

    with gr.Accordion("ℹ️ How HDP-P Works", open=False):
        gr.Markdown(textwrap.dedent("""
        ### Six-Gate PreExecutionGuard

        Before every robot motion, the guard runs six checks in order:

        | Gate | Checks |
        |------|--------|
        | 1 · Signature | Ed25519 signature on the EDT is valid |
        | 2 · class3_prohibited | Action is not Class 3 when the EDT forbids it |
        | 3 · class_ceiling | Action class ≤ EDT `max_class` |
        | 4 · excluded_zone | Target zone not in `excluded_zones` |
        | 5 · force_limit | `force_n` ≤ `max_force_n` |
        | 6 · velocity_limit | `velocity_ms` ≤ `max_velocity_ms` |

        ### Irreversibility Classes

        | Class | Meaning | Example |
        |-------|---------|---------|
        | 0 | Reversible (sensor/query) | Read joint angle |
        | 1 | Reversible with effort | Pick-and-place |
        | 2 | Normally irreversible | Press-fit, bonding |
        | 3 | Irreversible & harmful | Crush, max-speed override |

        ### Attack Scenario

        The injected command carries:
        - `force_n = 48 N` — exceeds EDT max (35 N) **and** exceeds 95 % of global threshold → **Class 3**
        - `zone = human-workspace` — in the EDT's `excluded_zones`
        - `description` contains `"crush"` + `"override"` + `"ignore limits"` — dangerous keywords

        The guard blocks at gate **2** (`class3_prohibited`) — the arm never moves.
        """))

    # ── Wire up events ────────────────────────────────────────────────────

    hdp_toggle.change(
        fn=toggle_hdp,
        inputs=[hdp_toggle],
        outputs=[hdp_label],
    )

    run_btn.click(
        fn=run_safe_routine,
        inputs=[hdp_toggle],
        outputs=[routine_log, routine_status, arm_state_store, diagram_out],
    )

    attack_btn.click(
        fn=inject_attack,
        inputs=[hdp_toggle],
        outputs=[attack_result, arm_state_store, diagram_out],
    )

    # Push arm state to Three.js canvas via JS
    arm_state_store.change(
        fn=None,
        inputs=[arm_state_store],
        outputs=[],
        js="(s) => { if(window._updateArmState) window._updateArmState(s); }",
    )

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo.launch()
