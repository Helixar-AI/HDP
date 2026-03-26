import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'

// @noble/ed25519 v3 requires setting the hash for sync methods
ed.hashes.sha512 = sha512

export interface KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export async function generateKeyPair(): Promise<KeyPair> {
  const { secretKey, publicKey } = await ed.keygenAsync()
  return { privateKey: secretKey, publicKey }
}

export function exportPublicKey(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString('base64url')
}

export function importPublicKey(b64url: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64url, 'base64url'))
}

export function exportPrivateKey(privateKey: Uint8Array): string {
  return Buffer.from(privateKey).toString('base64url')
}

export function importPrivateKey(b64url: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64url, 'base64url'))
}
