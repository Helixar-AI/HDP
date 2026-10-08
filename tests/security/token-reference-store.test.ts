// SPDX-License-Identifier: Apache-2.0
// tests/security/token-reference-store.test.ts
import { describe, expect, it } from 'vitest'
import { extendChain } from '../../src/chain/extender.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { issueToken } from '../../src/token/issuer.js'
import { verifyToken } from '../../src/token/verifier.js'
import {
  contentAddressedReference,
  resolveToken,
  storeToken,
  TokenReferenceIntegrityError,
} from '../../src/transport/reference.js'
import { InMemoryTokenStore } from '../../src/transport/store.js'
import type { TokenStore } from '../../src/transport/store.js'
import type { HdpToken } from '../../src/types/token.js'

interface TokenSnapshots {
  twoHopToken: HdpToken
  threeHopToken: HdpToken
  publicKey: Uint8Array
}

function copyToken(token: HdpToken): HdpToken {
  return JSON.parse(JSON.stringify(token)) as HdpToken
}

class MutableTokenStore implements TokenStore {
  private readonly entries = new Map<string, HdpToken>()

  async put(reference: string, token: HdpToken): Promise<void> {
    this.entries.set(reference, copyToken(token))
  }

  async get(reference: string): Promise<HdpToken | null> {
    const token = this.entries.get(reference)
    return token === undefined ? null : copyToken(token)
  }

  async delete(reference: string): Promise<void> {
    this.entries.delete(reference)
  }

  overwrite(reference: string, token: HdpToken): void {
    this.entries.set(reference, copyToken(token))
  }

  snapshot(): Map<string, HdpToken> {
    return new Map([...this.entries].map(([reference, token]) => [reference, copyToken(token)]))
  }

  restore(snapshot: Map<string, HdpToken>): void {
    this.entries.clear()
    for (const [reference, token] of snapshot) {
      this.entries.set(reference, copyToken(token))
    }
  }
}

async function createTokenSnapshots(): Promise<TokenSnapshots> {
  const { privateKey, publicKey } = await generateKeyPair()
  let twoHopToken = await issueToken({
    sessionId: 'store-conformance-session',
    principal: { id: 'principal-1', id_type: 'opaque' },
    scope: {
      intent: 'record a task',
      data_classification: 'public',
      network_egress: false,
      persistence: false,
      max_hops: 4,
    },
    signingKey: privateKey,
    keyId: 'store-conformance-key',
  })
  twoHopToken = await extendChain(twoHopToken, {
    agent_id: 'planner',
    agent_type: 'orchestrator',
    action_summary: 'plan task',
    parent_hop: 0,
  }, privateKey)
  twoHopToken = await extendChain(twoHopToken, {
    agent_id: 'worker',
    agent_type: 'sub-agent',
    action_summary: 'perform task',
    parent_hop: 1,
  }, privateKey)
  const threeHopToken = await extendChain(twoHopToken, {
    agent_id: 'tool',
    agent_type: 'tool',
    action_summary: 'complete task',
    parent_hop: 2,
  }, privateKey)

  await expectValid(twoHopToken, publicKey)
  await expectValid(threeHopToken, publicKey)

  return { twoHopToken, threeHopToken, publicKey }
}

async function expectValid(token: HdpToken, publicKey: Uint8Array): Promise<void> {
  const verification = await verifyToken(token, { publicKey })
  expect(verification.valid).toBe(true)
}

async function expectResolvedToken(
  store: TokenStore,
  reference: string,
  expected: HdpToken,
  publicKey: Uint8Array,
): Promise<HdpToken> {
  const token = await resolveToken(store, reference)
  expect(token).toEqual(expected)
  if (token === null) throw new Error('expected the reference to resolve to a token')
  await expectValid(token, publicKey)
  return token
}

async function expectReferenceError(operation: Promise<unknown>, message: string): Promise<void> {
  let failure: unknown
  try {
    await operation
  } catch (error: unknown) {
    failure = error
  }
  expect(failure).toBeInstanceOf(TokenReferenceIntegrityError)
  if (failure instanceof TokenReferenceIntegrityError) {
    expect(failure.message).toContain(message)
  }
}

describe('token reference store conformance', () => {
  // Section 8.2 says extensions use a new content reference while the UUID keeps its original snapshot.
  it('an extended token uses a new content reference while the UUID keeps its first snapshot', async () => {
    const { twoHopToken, threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new InMemoryTokenStore()
    const uuidReference = twoHopToken.header.token_id
    const extendedReference = contentAddressedReference(threeHopToken)

    await storeToken(store, twoHopToken)
    await storeToken(store, threeHopToken, extendedReference)

    await expectResolvedToken(store, uuidReference, twoHopToken, publicKey)
    await expectResolvedToken(store, extendedReference, threeHopToken, publicKey)
  })

  it('storing an extension under the UUID reference is rejected without changing stored snapshots', async () => {
    const { twoHopToken, threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new InMemoryTokenStore()
    const uuidReference = twoHopToken.header.token_id
    const originalContentReference = contentAddressedReference(twoHopToken)
    const extendedReference = contentAddressedReference(threeHopToken)

    await storeToken(store, twoHopToken)

    // Section 8.2 requires a reference to remain bound to the same complete token.
    await expectReferenceError(storeToken(store, threeHopToken), 'different token')
    await expectResolvedToken(store, uuidReference, twoHopToken, publicKey)
    await expectResolvedToken(store, originalContentReference, twoHopToken, publicKey)
    await expect(resolveToken(store, extendedReference)).resolves.toBeNull()
  })

  it('a content reference rejects a tail-truncated token on read', async () => {
    const { threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new MutableTokenStore()
    const uuidReference = threeHopToken.header.token_id
    const contentReference = contentAddressedReference(threeHopToken)
    const truncatedToken = copyToken(threeHopToken)
    truncatedToken.chain = truncatedToken.chain.slice(0, -1)

    await storeToken(store, threeHopToken)
    await expectValid(truncatedToken, publicKey)
    store.overwrite(uuidReference, truncatedToken)
    store.overwrite(contentReference, truncatedToken)

    // Section 8.2 requires checking the digest of the complete resolved token.
    await expectReferenceError(resolveToken(store, contentReference), 'digest mismatch')
  })

  it('a UUID reference can resolve a valid truncated token under the completeness limit in Section 10.4', async () => {
    const { threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new MutableTokenStore()
    const uuidReference = threeHopToken.header.token_id
    const contentReference = contentAddressedReference(threeHopToken)
    const truncatedToken = copyToken(threeHopToken)
    truncatedToken.chain = truncatedToken.chain.slice(0, -1)

    await storeToken(store, threeHopToken)
    store.overwrite(uuidReference, truncatedToken)
    store.overwrite(contentReference, truncatedToken)

    // Section 10.4 documents that trailing-hop deletion can leave integrity verification valid.
    // Section 8.2 says content references SHOULD be preferred when the resolver does not control the store.
    const resolved = await resolveToken(store, uuidReference)
    expect(resolved).not.toBeNull()
    if (resolved === null) throw new Error('expected the UUID reference to resolve')
    expect(resolved.chain).toHaveLength(2)
    await expectValid(resolved, publicKey)
  })

  it('a content reference returns null when rollback removes its snapshot', async () => {
    const { twoHopToken, threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new MutableTokenStore()
    const extendedReference = contentAddressedReference(threeHopToken)

    await storeToken(store, twoHopToken)
    const earlierStore = store.snapshot()
    await expectValid(threeHopToken, publicKey)
    await storeToken(store, threeHopToken, extendedReference)

    // Section 8.2 makes each extension a different content-addressed record.
    store.restore(earlierStore)

    await expect(resolveToken(store, extendedReference)).resolves.toBeNull()
  })

  it('a UUID reference continues to resolve the snapshot it first names after rollback', async () => {
    const { twoHopToken, threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new MutableTokenStore()
    const uuidReference = twoHopToken.header.token_id
    await storeToken(store, twoHopToken)
    const earlierStore = store.snapshot()

    const beforeRollback = await expectResolvedToken(store, uuidReference, twoHopToken, publicKey)
    await expectValid(threeHopToken, publicKey)
    await storeToken(store, threeHopToken, contentAddressedReference(threeHopToken))
    store.restore(earlierStore)
    const afterRollback = await expectResolvedToken(store, uuidReference, twoHopToken, publicKey)

    // Section 8.2 says a UUID reference identifies one immutable snapshot, not the latest chain.
    expect(afterRollback).toEqual(beforeRollback)
  })

  it('an older content reference resolves its matching snapshot after rollback', async () => {
    const { twoHopToken, threeHopToken, publicKey } = await createTokenSnapshots()
    const store = new MutableTokenStore()
    const originalContentReference = contentAddressedReference(twoHopToken)

    await storeToken(store, twoHopToken)
    const earlierStore = store.snapshot()
    await expectValid(threeHopToken, publicKey)
    await storeToken(store, threeHopToken, contentAddressedReference(threeHopToken))
    store.restore(earlierStore)

    // Section 10.4 says applications needing evidence of an observed or final record SHOULD retain
    // an authenticated receipt bound to its complete token digest.
    await expectResolvedToken(store, originalContentReference, twoHopToken, publicKey)
  })
})
