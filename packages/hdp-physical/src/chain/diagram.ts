// packages/hdp-physical/src/chain/diagram.ts
import type { AuthorizationDecision } from '../types/guard.js'

interface HopRecord {
  seq: number
  agent_id: string
  agent_type: string
  action_summary: string
  parent_hop: number
}

export function generateMermaidDiagram(
  chain: HopRecord[],
  decision: AuthorizationDecision
): string {
  const lines: string[] = [
    'flowchart TD',
    '  classDef approved fill:#166534,stroke:#22c55e,color:#dcfce7',
    '  classDef blocked fill:#7f1d1d,stroke:#ef4444,color:#fee2e2',
    '  classDef normal fill:#1e293b,stroke:#475569,color:#e2e8f0',
  ]

  const nodeId = (id: string) => id.replace(/[^a-zA-Z0-9]/g, '_')

  // Principal node
  lines.push(`  Principal["👤 Human Principal"]:::normal`)

  // Chain hops
  for (const hop of chain) {
    const nid = nodeId(`hop_${hop.seq}`)
    const label = `${hop.agent_type === 'orchestrator' ? '🔗' : '🤖'} ${hop.agent_id}\\n${hop.action_summary}`
    lines.push(`  ${nid}["${label}"]:::normal`)
  }

  // Guard node
  const guardClass = decision.approved ? 'normal' : 'blocked'
  const guardLabel = decision.approved
    ? `🛡️ HDP-P Guard\\nClass ${decision.classification} ✅`
    : `🛡️ HDP-P Guard\\n🚫 BLOCKED: ${decision.blocked_at}`
  lines.push(`  Guard["${guardLabel}"]:::${guardClass}`)

  // Actuator node
  const actuatorClass = decision.approved ? 'approved' : 'blocked'
  const actuatorLabel = decision.approved
    ? '⚙️ Actuator\\n✅ Executing'
    : '⚙️ Actuator\\n🚫 No action sent'
  lines.push(`  Actuator["${actuatorLabel}"]:::${actuatorClass}`)

  // Edges
  lines.push(`  Principal --> ${nodeId('hop_1')}`)
  for (let i = 0; i < chain.length - 1; i++) {
    lines.push(`  ${nodeId(`hop_${chain[i].seq}`)} --> ${nodeId(`hop_${chain[i + 1].seq}`)}`)
  }
  if (chain.length > 0) {
    lines.push(`  ${nodeId(`hop_${chain[chain.length - 1].seq}`)} --> Guard`)
  } else {
    lines.push(`  Principal --> Guard`)
  }
  lines.push(`  Guard --> Actuator`)

  return lines.join('\n')
}
