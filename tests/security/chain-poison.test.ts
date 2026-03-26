// tests/security/chain-poison.test.ts
import { describe, it, expect } from 'vitest'
import { validateChain } from '../../src/chain/validator.js'
import type { HopRecord } from '../../src/types/chain.js'

const hop = (seq: number, parent: number): HopRecord => ({
  seq, agent_id: `a${seq}`, agent_type: 'sub-agent', timestamp: seq * 1000, action_summary: 'x', parent_hop: parent, hop_signature: 'fake-sig-for-chain-structure-test'
})

describe('12.3 Chain Poisoning — Seq Gap Detection', () => {
  it('detects insertion of a hop with wrong seq (fabricated hop)', () => {
    // Attacker inserts a hop with seq=5 after seq=2 — fabricated hop
    expect(() => validateChain([hop(1, 0), hop(2, 1), hop(5, 2)], undefined)).toThrow('CHAIN_INTEGRITY')
  })

  it('detects duplicate seq values', () => {
    expect(() => validateChain([hop(1, 0), hop(1, 0), hop(2, 1)], undefined)).toThrow('CHAIN_INTEGRITY')
  })

  it('detects max_hops exceeded in validation', () => {
    expect(() => validateChain([hop(1, 0), hop(2, 1), hop(3, 2)], 2)).toThrow('MAX_HOPS_EXCEEDED')
  })
})
