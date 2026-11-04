/** Algorithm-specific half of a key-wrapper suite. Only `../key-wrapper.ts` selects one. */
export interface KeyWrapperSuiteImplementation {
  readonly privateKeyBytes: number
  readonly packageBytes: number
  /** Throws `recipient-mismatch` for a public key of the wrong length. */
  fingerprint(publicKey: Uint8Array, keyKind: number, protocolVersion: number): Uint8Array
  publicKeyFromPrivateKey(privateKey: Uint8Array): Promise<Uint8Array>
  seal(wrappedKey: Uint8Array, publicKey: Uint8Array, contextHash: Uint8Array): Promise<Uint8Array>
  /** Throws `open-failed` on any authentication or context failure. */
  open(sealedPackage: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array, contextHash: Uint8Array): Promise<Uint8Array>
}
