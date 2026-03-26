import { signHop } from '../crypto/sign.js'
import { validateChain } from './validator.js'
import { HdpMaxHopsExceededError } from '../types/errors.js'
import type { HdpToken } from '../types/token.js'
import type { ChainExtensionRequest, HopRecord, UnsignedHopRecord } from '../types/chain.js'

export async function extendChain(
  token: HdpToken,
  ext: ChainExtensionRequest,
  agentPrivateKey: Uint8Array
): Promise<HdpToken> {
  const currentChain = token.chain
  const nextSeq = currentChain.length + 1

  // Enforce max_hops BEFORE appending
  if (token.scope.max_hops !== undefined && nextSeq > token.scope.max_hops) {
    throw new HdpMaxHopsExceededError(token.scope.max_hops)
  }

  const unsignedHop: UnsignedHopRecord = {
    seq: nextSeq,
    agent_id: ext.agent_id,
    agent_type: ext.agent_type,
    timestamp: Date.now(),
    action_summary: ext.action_summary,
    parent_hop: ext.parent_hop,
    ...(ext.agent_fingerprint ? { agent_fingerprint: ext.agent_fingerprint } : {}),
  }

  // Sign over cumulative chain (including this hop) + root sig value
  const cumulativeForSigning = [...currentChain.map(h => ({ ...h })), unsignedHop]
  const hopSig = await signHop(cumulativeForSigning as HopRecord[], token.signature.value, agentPrivateKey)
  const signedHop: HopRecord = { ...unsignedHop, hop_signature: hopSig }

  const updatedChain = [...currentChain, signedHop]
  validateChain(updatedChain, token.scope.max_hops)

  return { ...token, chain: updatedChain }
}
