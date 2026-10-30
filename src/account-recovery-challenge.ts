import { fromBase64Url } from './encoding'
import { wipe } from './sodium'
import { loadSodium } from './sodium-loader'
import { decodeUuid } from './vault-v2-bytes'

export const ACCOUNT_RECOVERY_CHALLENGE_MAGIC = 'PLDNRCV1'
export const ACCOUNT_RECOVERY_PROOF_BYTES = 32
export const ACCOUNT_RECOVERY_CHALLENGE_PLAINTEXT_BYTES = 8 + 16 + ACCOUNT_RECOVERY_PROOF_BYTES
export const ACCOUNT_RECOVERY_CHALLENGE_SEALED_BYTES = ACCOUNT_RECOVERY_CHALLENGE_PLAINTEXT_BYTES + 48

const MAGIC = new TextEncoder().encode(ACCOUNT_RECOVERY_CHALLENGE_MAGIC)
const USER_ID_OFFSET = MAGIC.length
const SECRET_OFFSET = USER_ID_OFFSET + 16
const KEY_BYTES = 32

export class AccountRecoveryChallengeError extends Error {
  constructor() {
    super('Account recovery challenge rejected')
    this.name = 'AccountRecoveryChallengeError'
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

/**
 * Opens a `POST api/account/recovery/challenge` package with the account's
 * X25519 private key and returns the 32-byte `recoveryProof` (encode it with
 * `toBase64Url`, then `wipe` it).
 *
 * `userId` must come from the caller's authenticated session, never from the
 * challenge response. The magic and user binding stop a server from submitting
 * another sealed package addressed to the same key (for example a Vault-key
 * wrapper) and harvesting its plaintext as "proof".
 */
export async function openAccountRecoveryChallenge(
  sealedChallenge: string,
  userId: string,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  let opened: Uint8Array | undefined
  let publicKey: Uint8Array | undefined
  try {
    const expectedUserId = decodeUuid(userId)
    const sealed = fromBase64Url(sealedChallenge, ACCOUNT_RECOVERY_CHALLENGE_SEALED_BYTES)
    if (sealed.length !== ACCOUNT_RECOVERY_CHALLENGE_SEALED_BYTES || recipientPrivateKey.length !== KEY_BYTES) {
      throw new AccountRecoveryChallengeError()
    }
    const sodium = await loadSodium()
    publicKey = sodium.crypto_scalarmult_base(recipientPrivateKey)
    opened = sodium.crypto_box_seal_open(sealed, publicKey, recipientPrivateKey)
    if (opened.length !== ACCOUNT_RECOVERY_CHALLENGE_PLAINTEXT_BYTES
      || !equalBytes(opened.subarray(0, USER_ID_OFFSET), MAGIC)
      || !equalBytes(opened.subarray(USER_ID_OFFSET, SECRET_OFFSET), expectedUserId)) {
      throw new AccountRecoveryChallengeError()
    }
    return opened.slice(SECRET_OFFSET)
  } catch {
    throw new AccountRecoveryChallengeError()
  } finally {
    if (opened) wipe(opened)
    if (publicKey) wipe(publicKey)
  }
}
