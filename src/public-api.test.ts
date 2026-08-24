import { describe, expect, it } from 'vitest'
import * as publicApi from './index'

describe('public Protocol 2 API', () => {
  it('exposes only the frozen PLDNENV2 / PLDNKDF2 implementation', () => {
    expect(publicApi).toHaveProperty('encodeCanonicalEnvelopeAad')
    expect(publicApi).toHaveProperty('encodeCanonicalKdfContext')
    expect(publicApi).toHaveProperty('deriveVaultSubkey')
    expect(publicApi).toHaveProperty('buildScriptExecutionManifest')
    expect(publicApi).toHaveProperty('assertScriptExecutionPackage')
    expect(publicApi).toHaveProperty('sealScriptExecutionPackage')
    expect(publicApi).toHaveProperty('openScriptExecutionPackage')

    expect(publicApi).not.toHaveProperty('encodeVaultAad')
    expect(publicApi).not.toHaveProperty('assertEnvelopeBindings')
    expect(publicApi).not.toHaveProperty('deriveVaultProjectionKey')
    expect(publicApi).not.toHaveProperty('decodeBase64Url')
  })
})
