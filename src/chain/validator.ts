import type { HopRecord } from '../types/chain.js'
import { HdpChainIntegrityError, HdpMaxHopsExceededError } from '../types/errors.js'

export function validateChain(chain: HopRecord[], maxHops: number | undefined): void {
  if (chain.length === 0) return

  if (chain[0].seq !== 1) {
    throw new HdpChainIntegrityError('chain must start at seq 1')
  }

  for (let i = 0; i < chain.length; i++) {
    if (chain[i].seq !== i + 1) {
      throw new HdpChainIntegrityError(`seq gap: expected ${i + 1}, got ${chain[i].seq}`)
    }
  }

  if (maxHops !== undefined && chain.length > maxHops) {
    throw new HdpMaxHopsExceededError(maxHops)
  }
}
