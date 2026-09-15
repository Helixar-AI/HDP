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

  // An extension must never build on a malformed or already over-limit
  // chain.  Validate the prefix before calculating/signing the new hop so
  // callers cannot use extension as a way to bypass chain integrity checks.
  validateChain(currentChain, token.scope.max_hops)

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

  // Validate the structural rules that do not depend on the signature before
  // asking the signer to produce a signature.  The temporary value is only
  // used for validation and is never returned.
  validateChain(
    [...currentChain, { ...unsignedHop, hop_signature: 'pending' }],
    token.scope.max_hops,
  )

  // Sign over cumulative chain (including this hop) + root sig value
  const cumulativeForSigning = [...currentChain.map(h => ({ ...h })), unsignedHop]
  const hopSig = await signHop(cumulativeForSigning as HopRecord[], token.signature.value, agentPrivateKey)
  const signedHop: HopRecord = { ...unsignedHop, hop_signature: hopSig }

  const updatedChain = [...currentChain, signedHop]
  validateChain(updatedChain, token.scope.max_hops)

  return { ...token, chain: updatedChain }
}
