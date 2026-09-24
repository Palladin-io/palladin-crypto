# Local generator history (0.10.0 candidate)

`sealGeneratorHistory` and `openGeneratorHistory` encrypt an opaque client-owned
history document. They do not create Vault Entries or send data to the server.

The caller supplies the unlocked user's 32-byte private key and independently
authenticated account ID and configured API URL. The key is copied, then HKDF-SHA256
derives a 32-byte subkey with a zero 32-byte salt and UTF-8 JSON info:
`["palladin/local-generator-history/v1", accountId, apiUrl]`.
The exact account ID and API URL strings are binding; callers must use the same
canonical session values when sealing and opening. Never read expected scope from
the persisted envelope. Changing the private key makes old history inaccessible;
changing only the master password does not change this key.

The version-1 envelope contains only `version` and canonical base64url `ciphertext`.
Encryption uses the active provider's existing XSalsa20-Poly1305 format, including
a fresh 24-byte nonce and 16-byte authentication tag. Plaintext is limited to 2 MiB.
Origins, timestamps and generated values belong inside the encrypted document.

The caller owns retention, record validation and durable persistence. Persist
successfully before filling or copying a password. Failed decryption must not
silently replace history. Revalidate the unlocked session across asynchronous
work; wipe returned plaintext bytes and temporary key copies after use. JavaScript
strings and WebCrypto-internal key allocations cannot be explicitly zeroed.

This is an additive API candidate. Consumers require an exact reviewed 0.10.0
registry release; a local build is not evidence that registry installation works.
