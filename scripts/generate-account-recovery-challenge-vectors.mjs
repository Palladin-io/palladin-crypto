#!/usr/bin/env node
// Independent producer for the account recovery challenge fixtures. It seals with
// libsodium directly, never through the package implementation under test.
// crypto_box_seal uses a fresh ephemeral key, so every run emits different sealed
// bytes for the same synthetic keys, userId and secret; all of them stay valid.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import sodium from 'libsodium-wrappers';

await sodium.ready;

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(root, 'src/fixtures/account-recovery-challenge-v1/vectors.json');

const base64Url = (bytes) => Buffer.from(bytes).toString('base64url');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const uuidBytes = (value) => Buffer.from(value.replaceAll('-', ''), 'hex');
const filled = (length, value) => new Uint8Array(length).fill(value);
const ascii = (value) => new TextEncoder().encode(value);
const concat = (...parts) => Buffer.concat(parts.map((part) => Buffer.from(part)));

const recipientPrivateKey = filled(32, 0x55);
const recipientPublicKey = sodium.crypto_scalarmult_base(recipientPrivateKey);
const otherPrivateKey = filled(32, 0x66);
const otherPublicKey = sodium.crypto_scalarmult_base(otherPrivateKey);
const userId = '0b9e1b6c-5f3a-4d2e-9c41-7a8b6d5e4f30';
const otherUserId = '7d4c3b2a-1f0e-4a9b-8c7d-6e5f4a3b2c1d';
const secret = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const magic = ascii('PLDNRCV1');

const plaintext = concat(magic, uuidBytes(userId), secret);
const seal = (message, publicKey = recipientPublicKey) => base64Url(sodium.crypto_box_seal(message, publicKey));
const tampered = sodium.crypto_box_seal(plaintext, recipientPublicKey);
tampered[tampered.length - 1] ^= 0x01;

const vectors = {
  contract: 'palladin.account-recovery-challenge.v1',
  warning: 'Generated synthetic test material. Never use in production.',
  generator: 'scripts/generate-account-recovery-challenge-vectors.mjs',
  layout: 'crypto_box_seal("PLDNRCV1" || userId (16 B, RFC 4122 big-endian) || secret (32 B), accountX25519PublicKey)',
  recipientPrivateKey: base64Url(recipientPrivateKey),
  recipientPublicKey: base64Url(recipientPublicKey),
  userId,
  secret: base64Url(secret),
  plaintextHex: hex(plaintext),
  valid: { sealedChallenge: seal(plaintext), recoveryProof: base64Url(secret) },
  negative: [
    { name: 'wrong-magic', sealedChallenge: seal(concat(ascii('PLDNRCV2'), uuidBytes(userId), secret)) },
    { name: 'other-user-id', sealedChallenge: seal(concat(magic, uuidBytes(otherUserId), secret)) },
    { name: 'truncated-plaintext', sealedChallenge: seal(plaintext.subarray(0, plaintext.length - 1)) },
    { name: 'oversized-plaintext', sealedChallenge: seal(concat(plaintext, [0])) },
    {
      name: 'vault-key-wrapper-package',
      sealedChallenge: seal(concat(ascii('PLDNX2K1'), filled(32, 0x77), filled(32, 0x88))),
    },
    { name: 'sealed-to-other-key', sealedChallenge: seal(plaintext, otherPublicKey) },
    { name: 'tampered-ciphertext', sealedChallenge: base64Url(tampered) },
    { name: 'padded-base64url', sealedChallenge: `${seal(plaintext)}=` },
  ],
};

mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify(vectors, null, 2)}\n`);
