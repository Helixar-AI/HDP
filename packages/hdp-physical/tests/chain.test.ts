// packages/hdp-physical/tests/chain.test.ts
import { describe, it, expect } from 'vitest'
import { generateMermaidDiagram } from '../src/chain/diagram.js'
import { IrreversibilityClass } from '../src/types/edt.js'
import type { AuthorizationDecision } from '../src/types/guard.js'

const SAMPLE_CHAIN_HOPS = [
  { seq: 1, agent_id: 'human@helixar.ai', agent_type: 'orchestrator' as const, timestamp: 1700000000, action_summary: 'Issued EDT', parent_hop: 0, hop_signature: 'sig1' },
  { seq: 2, agent_id: 'gemma-4-e4b-it', agent_type: 'sub-agent' as const, timestamp: 1700000001, action_summary: 'Generated move_box command', parent_hop: 1, hop_signature: 'sig2' },
]

const APPROVED: AuthorizationDecision = {
  approved: true, classification: IrreversibilityClass.REVERSIBLE_WITH_EFFORT,
  reason: 'Standard manipulation', edt_valid: true, blocked_at: null,
}

const BLOCKED: AuthorizationDecision = {
  approved: false, classification: IrreversibilityClass.IRREVERSIBLE_AND_HARMFUL,
  reason: 'Class 3 rejected', edt_valid: false, blocked_at: 'signature',
}

describe('generateMermaidDiagram', () => {
  it('produces valid Mermaid flowchart syntax', () => {
    const diagram = generateMermaidDiagram(SAMPLE_CHAIN_HOPS, APPROVED)
    expect(diagram).toContain('flowchart TD')
    expect(diagram).toContain('human@helixar.ai')
    expect(diagram).toContain('gemma-4-e4b-it')
    expect(diagram).toContain('HDP-P Guard')
    expect(diagram).toContain('Actuator')
  })

  it('marks the actuator node green when approved', () => {
    const diagram = generateMermaidDiagram(SAMPLE_CHAIN_HOPS, APPROVED)
    expect(diagram).toContain(':::approved')
  })

  it('marks the guard node red when blocked', () => {
    const diagram = generateMermaidDiagram(SAMPLE_CHAIN_HOPS, BLOCKED)
    expect(diagram).toContain(':::blocked')
  })
})
