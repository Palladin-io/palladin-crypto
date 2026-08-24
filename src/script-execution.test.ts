import { describe, expect, it } from 'vitest'

import {
  assertScriptExecutionPackage,
  buildScriptExecutionManifest,
  buildScriptExecutionPackageBinding,
  effectiveReturnResultToAgent,
  encodeScriptExecutionManifest,
  encodeScriptExecutionParameters,
  openScriptExecutionPackage,
  parseScriptExecutionManifest,
  refreshScriptExecutionPackage,
  refreshScriptExecutionPackageBinding,
  sealScriptExecutionPackage,
  scriptExecutionDiscovery,
  validateScriptExecutionParameters,
  type ScriptExecutionAuthorizationV1,
  type ScriptExecutionPackageScopeV1,
} from './script-execution'
import { encodeMemberSecret, parseMemberSecret, type MemberSecretV1 } from './vault-plaintext'
import { loadSodium } from './sodium-loader'

const organizationId = '11111111-1111-4111-8111-111111111111'
const agentId = '22222222-2222-4222-8222-222222222222'
const vaultId = '33333333-3333-4333-8333-333333333333'
const scriptEntryId = '44444444-4444-4444-8444-444444444444'
const passwordEntryId = '55555555-5555-4555-8555-555555555551'
const hostEntryId = '55555555-5555-4555-8555-555555555552'
const portEntryId = '55555555-5555-4555-8555-555555555553'
const userEntryId = '55555555-5555-4555-8555-555555555554'

const secret: MemberSecretV1 = {
  schema: 'palladin.member-secret.v1',
  entryType: 'script',
  memberLabel: 'Test SQL users',
  agentLabel: 'List database users',
  discoverable: true,
  description: null,
  icon: null,
  color: null,
  content: {
    source: 'const input = JSON.parse(require("fs").readFileSync(0, "utf8"));\nprocess.stdout.write(JSON.stringify({ limit: input.limit }));',
    interpreter: 'node',
    refs: [
      { env: 'DB_PASSWORD', vaultId, entryId: passwordEntryId, fieldId: 'credential.password' },
      { env: 'DB_HOST', vaultId, entryId: hostEntryId, fieldId: 'credential.url' },
      { env: 'DB_PORT', vaultId, entryId: portEntryId, fieldId: 'key.value' },
      { env: 'DB_USER', vaultId, entryId: userEntryId, fieldId: 'credential.username' },
    ],
    execution: {
      contractVersion: 1,
      description: 'Pobiera użytkowników z bazy',
      parameters: [
        { name: 'limit', description: 'Maksymalna liczba użytkowników', type: 'integer', required: true, minimum: 1, maximum: 100 },
        { name: 'activeOnly', description: 'Tylko aktywni użytkownicy', type: 'boolean', required: true },
        { name: 'role', description: 'Filtr roli', type: 'string', required: false, enum: ['admin', 'member', 'viewer'] },
      ],
      returnResultToAgent: true,
    },
    notes: null,
    customFields: [],
  },
  agentFieldAccess: {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never', entryType: 'discovery',
    'script.source': 'onGrantRuntime', 'script.interpreter': 'discovery', 'script.refs': 'onGrantRuntime', notes: 'never',
  },
}

const referenceRevisions = {
  [passwordEntryId]: '6',
  [hostEntryId]: '3',
  [portEntryId]: '1',
  [userEntryId]: '4',
}

function manifest() {
  return buildScriptExecutionManifest({
    organizationId,
    agentId,
    agentAccessEpoch: 3,
    vaultId,
    scriptEntryId,
    scriptRevision: '7',
    memberSecret: secret,
    referenceRevisions,
  })
}

const directAuthorization: ScriptExecutionAuthorizationV1 = {
  source: 'scriptExecution',
  grantId: '66666666-6666-4666-8666-666666666666',
}

const credentialReference: MemberSecretV1 = {
  schema: 'palladin.member-secret.v1',
  entryType: 'credential',
  memberLabel: 'SQL fixture credential',
  agentLabel: 'SQL connection',
  discoverable: true,
  description: null,
  icon: null,
  color: null,
  content: {
    username: 'fixture_user',
    password: 'fixture_password_never_production',
    url: 'db.fixture.invalid',
    urlDomain: 'fixture.invalid',
    totp: null,
    notes: null,
    customFields: [],
  },
  agentFieldAccess: {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
    entryType: 'discovery', 'credential.username': 'onGrantValue', 'credential.password': 'onGrantValue',
    'credential.url': 'onGrantValue', 'credential.urlDomain': 'discovery', 'credential.totp': 'never', notes: 'never',
  },
}

const keyReference: MemberSecretV1 = {
  schema: 'palladin.member-secret.v1',
  entryType: 'key',
  memberLabel: 'SQL fixture port',
  agentLabel: 'SQL port',
  discoverable: true,
  description: null,
  icon: null,
  color: null,
  content: { value: '5432', notes: null, customFields: [] },
  agentFieldAccess: {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
    entryType: 'discovery', 'key.value': 'onGrantValue', notes: 'never',
  },
}

function packageEntries() {
  return [
    { entryId: hostEntryId, entryRevision: '3', encodedMemberSecret: encodeMemberSecret(credentialReference) },
    { entryId: passwordEntryId, entryRevision: '6', encodedMemberSecret: encodeMemberSecret(credentialReference) },
    { entryId: portEntryId, entryRevision: '1', encodedMemberSecret: encodeMemberSecret(keyReference) },
    { entryId: userEntryId, entryRevision: '4', encodedMemberSecret: encodeMemberSecret(credentialReference) },
  ]
}

function expectedContext(scriptRevision = '7') {
  return {
    organizationId,
    vaultId,
    agentId,
    agentAccessEpoch: 3,
    scriptEntryId,
    scriptRevision,
    recipientAgentKeyVersion: 2,
  }
}

describe('Script execution package', () => {
  it('builds one canonical manifest and exposes only discovery metadata to the Agent', () => {
    const value = manifest()
    expect(value.parameters.map((item) => item.name)).toEqual(['activeOnly', 'limit', 'role'])
    expect(value.references.map((item) => item.env)).toEqual(['DB_HOST', 'DB_PASSWORD', 'DB_PORT', 'DB_USER'])
    expect(scriptExecutionDiscovery(value)).toEqual({
      contractVersion: 1,
      description: 'Pobiera użytkowników z bazy',
      parameters: value.parameters,
      returnResultToAgent: true,
    })
    expect(scriptExecutionDiscovery(value)).not.toHaveProperty('scriptSource')
    expect(scriptExecutionDiscovery(value)).not.toHaveProperty('references')
    expect(parseScriptExecutionManifest(encodeScriptExecutionManifest(value))).toEqual(value)
  })

  it('defaults a missing result policy to false without changing existing Scripts', () => {
    expect(effectiveReturnResultToAgent(undefined)).toBe(false)
    expect(effectiveReturnResultToAgent({})).toBe(false)
    const legacy = structuredClone(secret)
    if (legacy.entryType !== 'script' || !legacy.content.execution) throw new Error('fixture')
    delete legacy.content.execution.returnResultToAgent
    const value = buildScriptExecutionManifest({
      organizationId, agentId, agentAccessEpoch: 3, vaultId, scriptEntryId,
      scriptRevision: '7', memberSecret: legacy, referenceRevisions,
    })
    expect(value.returnResultToAgent).toBe(false)
  })

  it('rejects reserved and case-insensitively duplicated reference environment names', () => {
    const reserved = structuredClone(secret)
    if (reserved.entryType !== 'script') throw new Error('fixture')
    reserved.content.refs[0].env = 'NODE_OPTIONS'
    expect(() => buildScriptExecutionManifest({
      organizationId, agentId, agentAccessEpoch: 3, vaultId, scriptEntryId,
      scriptRevision: '7', memberSecret: reserved, referenceRevisions,
    })).toThrow(/reserved or invalid/)

    const duplicated = structuredClone(secret)
    if (duplicated.entryType !== 'script') throw new Error('fixture')
    duplicated.content.refs[1].env = 'db_password'
    expect(() => buildScriptExecutionManifest({
      organizationId, agentId, agentAccessEpoch: 3, vaultId, scriptEntryId,
      scriptRevision: '7', memberSecret: duplicated, referenceRevisions,
    })).toThrow(/must be unique/)
  })

  it('validates and canonically encodes typed parameters before a package request', () => {
    const definitions = manifest().parameters
    expect(validateScriptExecutionParameters(definitions, { limit: 25, activeOnly: true, role: 'member' }))
      .toEqual({ activeOnly: true, limit: 25, role: 'member' })
    expect(new TextDecoder().decode(encodeScriptExecutionParameters(definitions, { limit: 25, activeOnly: true })))
      .toBe('{"activeOnly":true,"limit":25}')
    expect(() => validateScriptExecutionParameters(definitions, { activeOnly: true })).toThrow(/required/)
    expect(() => validateScriptExecutionParameters(definitions, { activeOnly: true, limit: 25, debug: true })).toThrow(/undeclared/)
    expect(() => validateScriptExecutionParameters(definitions, { activeOnly: true, limit: '25' })).toThrow(/type/)
    expect(() => validateScriptExecutionParameters(definitions, { activeOnly: true, limit: 25, role: 'owner' })).toThrow(/enum/)
  })

  it('binds exactly one authorization and the complete Script plus reference scope set', async () => {
    const value = manifest()
    const binding = await buildScriptExecutionPackageBinding(value, directAuthorization)
    const opened: ScriptExecutionPackageScopeV1[] = binding.scopes.map((scope) => ({ ...scope }))
    await expect(assertScriptExecutionPackage(binding, value, opened)).resolves.toBeUndefined()
    await expect(assertScriptExecutionPackage(binding, value, opened.slice(0, -1))).rejects.toThrow(/incomplete/)
    await expect(assertScriptExecutionPackage(binding, value, [...opened, opened[0]])).rejects.toThrow(/unique/)
    await expect(assertScriptExecutionPackage({ ...binding, agentId: organizationId }, value, opened)).rejects.toThrow(/does not match/)
  })

  it('preserves the durable direct grant identity on binding refresh and rejects per-Script FULL material', async () => {
    const current = await buildScriptExecutionPackageBinding(manifest(), directAuthorization)
    const nextManifest = { ...manifest(), scriptRevision: '8', description: 'Pobiera aktywnych użytkowników z bazy' }
    const refreshed = await refreshScriptExecutionPackageBinding(current, nextManifest)
    expect(refreshed.authorization).toEqual(directAuthorization)
    expect(refreshed.scriptRevision).toBe('8')
    expect(refreshed.manifestDigest).not.toBe(current.manifestDigest)

    const full = await buildScriptExecutionPackageBinding(manifest(), { ...directAuthorization, source: 'full' })
    await expect(refreshScriptExecutionPackageBinding(full, nextManifest)).rejects.toThrow(/do not carry/)
  })

  it('seals and opens one opaque direct package and increments only packageRevision on refresh', async () => {
    const sodium = await loadSodium()
    const recipient = sodium.crypto_box_keypair()
    const sealed = await sealScriptExecutionPackage({
      manifest: manifest(),
      grantId: directAuthorization.grantId,
      packageRevision: '1',
      recipientAgentKeyVersion: 2,
      recipientAgentPublicKey: recipient.publicKey,
      entries: packageEntries(),
    })

    expect(sealed.grantId).toBe(directAuthorization.grantId)
    expect(sealed.packageRevision).toBe('1')
    expect(sealed.scopes).toHaveLength(5)
    expect(JSON.stringify(sealed)).not.toContain('fixture_password_never_production')
    expect(JSON.stringify(sealed)).not.toContain('Pobiera użytkowników')

    const opened = await openScriptExecutionPackage(sealed, recipient.privateKey, expectedContext())
    expect(opened.manifest).toEqual(manifest())
    expect(opened.entries).toHaveLength(4)
    expect(parseMemberSecret(opened.entries.find((entry) => entry.entryId === passwordEntryId)!.encodedMemberSecret))
      .toEqual(credentialReference)

    const nextManifest = { ...manifest(), scriptRevision: '8', description: 'Pobiera aktywnych użytkowników z bazy' }
    const refreshed = await refreshScriptExecutionPackage(
      sealed,
      nextManifest,
      packageEntries(),
      recipient.publicKey,
    )
    expect(refreshed.grantId).toBe(sealed.grantId)
    expect(refreshed.packageRevision).toBe('2')
    expect((await openScriptExecutionPackage(refreshed, recipient.privateKey, expectedContext('8'))).manifest).toEqual(nextManifest)
  })

  it('rejects an incomplete package, a substituted recipient and ciphertext tampering', async () => {
    const sodium = await loadSodium()
    const recipient = sodium.crypto_box_keypair()
    const attacker = sodium.crypto_box_keypair()
    await expect(sealScriptExecutionPackage({
      manifest: manifest(),
      grantId: directAuthorization.grantId,
      packageRevision: '1',
      recipientAgentKeyVersion: 1,
      recipientAgentPublicKey: recipient.publicKey,
      entries: packageEntries().slice(0, -1),
    })).rejects.toThrow(/incomplete/)

    const sealed = await sealScriptExecutionPackage({
      manifest: manifest(),
      grantId: directAuthorization.grantId,
      packageRevision: '1',
      recipientAgentKeyVersion: 1,
      recipientAgentPublicKey: recipient.publicKey,
      entries: packageEntries(),
    })
    await expect(openScriptExecutionPackage(sealed, attacker.privateKey, {
      ...expectedContext(),
      recipientAgentKeyVersion: 1,
    })).rejects.toThrow(/recipient/)
    await expect(openScriptExecutionPackage(sealed, recipient.privateKey, {
      ...expectedContext(),
      recipientAgentKeyVersion: 1,
      scriptRevision: '8',
    })).rejects.toThrow(/requested execution context/)
    const last = sealed.encodedPackageCiphertext.at(-1)!
    const tampered = {
      ...sealed,
      encodedPackageCiphertext: `${sealed.encodedPackageCiphertext.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`,
    }
    await expect(openScriptExecutionPackage(tampered, recipient.privateKey, {
      ...expectedContext(),
      recipientAgentKeyVersion: 1,
    })).rejects.toBeDefined()
  })

  it('rejects missing, cross-Vault, duplicate, stale and substituted material fail closed', async () => {
    expect(() => buildScriptExecutionManifest({
      organizationId, agentId, agentAccessEpoch: 3, vaultId, scriptEntryId,
      scriptRevision: '7', memberSecret: secret, referenceRevisions: {},
    })).toThrow(/revision is missing/)
    const crossVault = structuredClone(secret)
    if (crossVault.entryType !== 'script') throw new Error('fixture')
    crossVault.content.refs[0].vaultId = organizationId
    expect(() => buildScriptExecutionManifest({
      organizationId, agentId, agentAccessEpoch: 3, vaultId, scriptEntryId,
      scriptRevision: '7', memberSecret: crossVault, referenceRevisions,
    })).toThrow(/Cross-Vault/)

    const value = manifest()
    const binding = await buildScriptExecutionPackageBinding(value, directAuthorization)
    const stale = binding.scopes.map((scope) => scope.entryId === passwordEntryId ? { ...scope, entryRevision: '5' } : scope)
    await expect(assertScriptExecutionPackage(binding, value, stale)).rejects.toThrow(/incomplete or substituted/)
  })
})
