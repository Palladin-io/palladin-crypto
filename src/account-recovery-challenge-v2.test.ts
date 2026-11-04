import { describe, expect, it } from 'vitest'
import { AccountRecoveryChallengeError, openAccountRecoveryChallengeV2 } from './account-recovery-challenge'
import { fromBase64Url, toBase64Url } from './encoding'
import keyWrapperVectors from './fixtures/key-wrapper-v1/vectors.json'
import v3 from './fixtures/identity-kdf-v3/vectors.json'
import { decodeHex } from './vault-v2-bytes'

const vector = v3.recoveryChallenge
const seed = () => decodeHex(vector.memberSeedHex)

describe('openAccountRecoveryChallengeV2', () => {
  it('returns the secret of the vector challenge bound to the caller', async () => {
    expect(toBase64Url(await openAccountRecoveryChallengeV2(vector.package, vector.userId, seed()))).toBe(vector.secretBase64url)
  })

  it.each([
    ['another user id', vector.package, vector.negative[0].userId, seed()],
    ['another member key', vector.package, vector.userId, new Uint8Array(32).fill(0x42)],
    ['a truncated package', toBase64Url(fromBase64Url(vector.package).subarray(1)), vector.userId, seed()],
    ['a flipped AEAD tag', toBase64Url(fromBase64Url(vector.package).map((byte, index) => index === 1167 ? byte ^ 1 : byte)), vector.userId, seed()],
    ['a short seed', vector.package, vector.userId, new Uint8Array(31)],
  ])('rejects %s', async (_case, challenge, userId, key) => {
    await expect(openAccountRecoveryChallengeV2(challenge, userId, key)).rejects.toThrow(AccountRecoveryChallengeError)
  })

  it('cannot open a key-wrapper package addressed to the same member key', async () => {
    const wrapper = keyWrapperVectors.positive.find(({ name }) => name === 'palladin-xwing-v1:member-vault-key:key-kind-5')!
    await expect(openAccountRecoveryChallengeV2(
      wrapper.encodedSealedKeyPackage,
      wrapper.descriptor.scope.memberId!,
      decodeHex(wrapper.recipient.privateKeyHex),
    )).rejects.toThrow(AccountRecoveryChallengeError)
  })
})
