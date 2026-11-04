import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js'
import { describe, expect, it } from 'vitest'
import {
  computePairingSas,
  encodePairingOffer,
  encodePairingQr,
  generatePairingKeyPair,
  openPairingEnvelope,
  pairingRecipientKeyDigest,
  PairingError,
  parsePairingQr,
  sealAccountSecretForPairing,
  type PairingSession,
} from './device-pairing'
import { fromBase64Url, toBase64Url } from './encoding'
import v3 from './fixtures/identity-kdf-v3/vectors.json'
import { decodeHex, encodeHex } from './vault-v2-bytes'

const vector = v3.devicePairing
const recipientKeyPair = (() => {
  const privateKey = decodeHex(vector.recipientSeedHex)
  return { privateKey, publicKey: xwing.keygen(privateKey).publicKey }
})()
const session: PairingSession = {
  accountId: vector.accountId,
  transferId: vector.transferIdBase64url,
  challenge: vector.challengeBase64url,
  recipientPublicKey: recipientKeyPair.publicKey,
}
const accountSecret = fromBase64Url(vector.accountSecretBase64url)

async function pairingErrorCode(action: () => unknown): Promise<string | undefined> {
  try {
    await action()
  } catch (error) {
    return error instanceof PairingError ? error.code : `unexpected: ${String(error)}`
  }
  return undefined
}

describe('device pairing v2 vectors', () => {
  it('encodes and parses both QR payloads', () => {
    const digest = pairingRecipientKeyDigest(recipientKeyPair.publicKey)
    expect(digest).toBe(vector.recipientPublicKeySha256Base64url)
    const recipientQr = { flow: 'recipient-shows-qr', transferId: vector.transferIdBase64url, recipientPublicKeyDigest: digest } as const
    const senderQr = { flow: 'sender-shows-qr', transferId: vector.transferIdBase64url, challenge: vector.challengeBase64url } as const
    expect(encodePairingQr(recipientQr)).toBe(vector.qrRecipientShows)
    expect(encodePairingQr(senderQr)).toBe(vector.qrSenderShows)
    expect(parsePairingQr(vector.qrRecipientShows)).toEqual(recipientQr)
    expect(parsePairingQr(vector.qrSenderShows)).toEqual(senderQr)
  })

  it.each([
    vector.qrRecipientShows.replace(':v2:', ':v1:'),
    `${vector.qrSenderShows}.extra`,
    vector.qrSenderShows.slice(0, -1),
    `${vector.qrSenderShows}=`,
  ])('rejects malformed QR %s', async (payload) => {
    expect(await pairingErrorCode(() => parsePairingQr(payload))).toBe('malformed-qr')
  })

  it('matches the offer bytes and SAS, and the SAS changes with the account', () => {
    expect(encodeHex(encodePairingOffer(session))).toBe(vector.offerBytesHex)
    expect(computePairingSas(session)).toBe(vector.sas)
    const [wrongAccount] = vector.negative
    expect(computePairingSas({ ...session, accountId: wrongAccount.accountId! })).not.toBe(vector.sas)
  })

  it('opens the vector envelope and rejects a substituted challenge', async () => {
    expect(await openPairingEnvelope(session, recipientKeyPair, vector.envelope)).toEqual(accountSecret)
    const wrongChallenge = vector.negative[1]
    expect(await pairingErrorCode(() => openPairingEnvelope(
      { ...session, challenge: wrongChallenge.challengeBase64url! }, recipientKeyPair, vector.envelope,
    ))).toBe('aead-failure')
  })
})

describe('device pairing v2 round trip', () => {
  it('delivers the Account Secret in both flows', async () => {
    const recipient = await generatePairingKeyPair()
    const live = { ...session, recipientPublicKey: recipient.publicKey }
    const scanned = parsePairingQr(encodePairingQr({
      flow: 'recipient-shows-qr', transferId: live.transferId, recipientPublicKeyDigest: pairingRecipientKeyDigest(recipient.publicKey),
    }))
    if (scanned.flow !== 'recipient-shows-qr') throw new Error('unexpected flow')
    const fromScan = await sealAccountSecretForPairing({
      ...live, sasConfirmed: true, flow: 'recipient-shows-qr', scannedRecipientPublicKeyDigest: scanned.recipientPublicKeyDigest,
    }, accountSecret)
    expect(await openPairingEnvelope(live, recipient, fromScan)).toEqual(accountSecret)

    const fromSender = await sealAccountSecretForPairing({ ...live, sasConfirmed: true, flow: 'sender-shows-qr' }, accountSecret)
    expect(fromSender.kemCiphertext).not.toBe(fromScan.kemCiphertext)
    expect(await openPairingEnvelope(live, recipient, fromSender)).toEqual(accountSecret)
  })

  it('creates no envelope for a backend-substituted recipient key or without SAS confirmation', async () => {
    const attacker = await generatePairingKeyPair()
    expect(await pairingErrorCode(() => sealAccountSecretForPairing({
      ...session,
      recipientPublicKey: attacker.publicKey,
      sasConfirmed: true,
      flow: 'recipient-shows-qr',
      scannedRecipientPublicKeyDigest: vector.recipientPublicKeySha256Base64url,
    }, accountSecret))).toBe('recipient-key-digest-mismatch')
    expect(computePairingSas({ ...session, recipientPublicKey: attacker.publicKey })).not.toBe(vector.sas)

    const unconfirmed = { ...session, sasConfirmed: false, flow: 'sender-shows-qr' } as unknown as Parameters<typeof sealAccountSecretForPairing>[0]
    expect(await pairingErrorCode(() => sealAccountSecretForPairing(unconfirmed, accountSecret))).toBe('sas-not-confirmed')
  })

  it('fails closed for another device key and malformed envelopes', async () => {
    const other = await generatePairingKeyPair()
    expect(await pairingErrorCode(() => openPairingEnvelope(session, other, vector.envelope))).toBe('aead-failure')
    expect(await pairingErrorCode(() => openPairingEnvelope(session, recipientKeyPair, {
      ...vector.envelope, kemCiphertext: toBase64Url(fromBase64Url(vector.envelope.kemCiphertext).subarray(1)),
    }))).toBe('malformed-envelope')
    expect(await pairingErrorCode(() => openPairingEnvelope(session, recipientKeyPair, {
      ...vector.envelope, ciphertext: `${vector.envelope.ciphertext}AA`,
    }))).toBe('malformed-envelope')
  })
})
