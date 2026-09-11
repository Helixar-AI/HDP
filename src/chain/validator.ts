import type { HopRecord } from '../types/chain.js'
import { HdpChainIntegrityError, HdpMaxHopsExceededError } from '../types/errors.js'

export function validateChain(chain: HopRecord[], maxHops: number | undefined): void {
  if (chain.length === 0) return

  if (chain[0].seq !== 1) {
    throw new HdpChainIntegrityError('chain must start at seq 1')
  }

  for (let i = 0; i < chain.length; i++) {
    const hop = chain[i]

    if (hop.seq !== i + 1) {
      throw new HdpChainIntegrityError(`seq gap: expected ${i + 1}, got ${hop.seq}`)
    }

    // A parent can be the root authorization (0), or any hop that has
    // already appeared in the chain.  In particular, a hop must not point
    // to itself or to a later hop.
    if (!Number.isSafeInteger(hop.parent_hop) || hop.parent_hop < 0 || hop.parent_hop >= hop.seq) {
      throw new HdpChainIntegrityError(`invalid parent_hop ${hop.parent_hop} for seq ${hop.seq}`)
    }

    if (!Number.isSafeInteger(hop.timestamp) || hop.timestamp < 0) {
      throw new HdpChainIntegrityError(`invalid timestamp for seq ${hop.seq}`)
    }

    if (typeof hop.hop_signature !== 'string' || hop.hop_signature.length === 0) {
      throw new HdpChainIntegrityError(`missing hop_signature for seq ${hop.seq}`)
    }

    if (i > 0 && hop.timestamp < chain[i - 1].timestamp) {
      throw new HdpChainIntegrityError(
        `timestamp decreased at seq ${hop.seq}: ${hop.timestamp} < ${chain[i - 1].timestamp}`,
      )
    }
  }

  if (maxHops !== undefined && chain.length > maxHops) {
    throw new HdpMaxHopsExceededError(maxHops)
  }
}
