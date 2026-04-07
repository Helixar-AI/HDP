"""Mermaid chain-of-delegation diagram generator for HDP-P.

Produces a Mermaid ``flowchart TD`` diagram showing the delegation chain from
the human principal through to the robot action, with approved / blocked
styling.

Usage::

    from hdp_physical.chain import generate_mermaid_diagram
    from hdp_physical.types import AuthorizationDecision, IrreversibilityClass, SignedEdt

    diagram = generate_mermaid_diagram(signed_edt, decision)
    print(diagram)
"""

from __future__ import annotations

from typing import Optional

from hdp_physical.types import AuthorizationDecision, SignedEdt


def generate_mermaid_diagram(
    signed_edt: SignedEdt,
    decision: AuthorizationDecision,
    action_label: Optional[str] = None,
) -> str:
    """Generate a Mermaid flowchart showing the HDP-P delegation chain.

    Parameters
    ----------
    signed_edt:
        The signed EDT whose fields are used to label the diagram nodes.
    decision:
        The :class:`AuthorizationDecision` produced by :class:`PreExecutionGuard`.
    action_label:
        Human-readable label for the action node.  Defaults to the platform ID.

    Returns
    -------
    str
        A Mermaid ``flowchart TD`` diagram string.
    """
    edt = signed_edt.edt
    platform = edt.embodiment.platform_id
    agent_type = edt.embodiment.agent_type
    workspace = edt.embodiment.workspace_scope
    kid = signed_edt.kid
    max_class = int(edt.irreversibility.max_class)
    class3_prohibited = edt.irreversibility.class3_prohibited
    action_class = int(decision.classification)
    approved = decision.approved
    blocked_at = decision.blocked_at or ""

    action_node_label = action_label or f"{agent_type} action"
    robot_node_label = f"{platform} / {workspace}\\n{action_node_label}"

    # Determine node CSS classes
    approved_class = "approved" if approved else "blocked"

    # Build EDT summary line
    edt_label = (
        f"EDT [{kid}]\\n"
        f"max_class={max_class} "
        f"class3_prohibited={'true' if class3_prohibited else 'false'}"
    )

    # Guard result node
    if approved:
        guard_result = "✅ Approved"
        guard_label = f"guard_result[{guard_result}]"
    else:
        guard_result = f"🛑 Blocked at {blocked_at}"
        guard_label = f"guard_result[{guard_result}]"

    action_class_label = f"Class {action_class}"

    lines = [
        "flowchart TD",
        f'    classDef approved fill:#16a34a,color:#fff,stroke:#15803d',
        f'    classDef blocked fill:#dc2626,color:#fff,stroke:#b91c1c',
        "",
        f'    human["👤 Human Principal"]',
        f'    edt["{edt_label}"]',
        f'    classifier["🔍 IrreversibilityClassifier\\nresult={action_class_label}"]',
        f'    guard["🛡️ PreExecutionGuard"]',
        f'    {guard_label}',
        f'    robot["🤖 {robot_node_label}"]',
        "",
        f'    human -->|signs EDT| edt',
        f'    edt -->|authorizes| guard',
        f'    classifier -->|{action_class_label}| guard',
        f'    guard --> guard_result',
    ]

    if approved:
        lines.append(f'    guard_result -->|execute| robot')
        lines.append(f'    guard_result:::approved')
    else:
        lines.append(f'    guard_result:::blocked')

    return "\n".join(lines)
