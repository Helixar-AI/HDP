import { describe, it, expect } from 'vitest'
import { validateChain } from '../../src/chain/validator.js'
import type { HopRecord } from '../../src/types/chain.js'

const hop = (seq: number, parent: number): HopRecord => ({
  seq, agent_id: `a${seq}`, agent_type: 'sub-agent', timestamp: seq * 1000, action_summary: 'x', parent_hop: parent, hop_signature: 'fake-sig'
})

describe('validateChain', () => {
  it('accepts an empty chain', () => {
    expect(() => validateChain([], undefined)).not.toThrow()
  })

  it('accepts a valid linear chain', () => {
    expect(() => validateChain([hop(1, 0), hop(2, 1), hop(3, 2)], undefined)).not.toThrow()
  })

  it('rejects non-contiguous seq values', () => {
    expect(() => validateChain([hop(1, 0), hop(3, 1)], undefined)).toThrow('CHAIN_INTEGRITY')
  })

  it('rejects chain exceeding max_hops', () => {
    expect(() => validateChain([hop(1, 0), hop(2, 1), hop(3, 2)], 2)).toThrow('MAX_HOPS_EXCEEDED')
  })

  it('rejects chain not starting at seq 1', () => {
    expect(() => validateChain([hop(2, 0)], undefined)).toThrow('CHAIN_INTEGRITY')
  })

  it('rejects a hop whose parent is not a prior hop or the root', () => {
    expect(() => validateChain([hop(1, 0), hop(2, 2)], undefined)).toThrow('CHAIN_INTEGRITY')
    expect(() => validateChain([hop(1, 0), hop(2, -1)], undefined)).toThrow('CHAIN_INTEGRITY')
  })

  it('rejects decreasing hop timestamps', () => {
    expect(() => validateChain([hop(1, 2000), hop(2, 1000)], undefined)).toThrow('CHAIN_INTEGRITY')
  })

  it('rejects a hop without a signature', () => {
    const unsigned = { ...hop(1, 0), hop_signature: '' }
    expect(() => validateChain([unsigned], undefined)).toThrow('CHAIN_INTEGRITY')
  })
})
