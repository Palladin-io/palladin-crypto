import { z } from 'zod'

import { MAX_ENCODED_SUITE_PAYLOAD_BYTES, requireCryptoSuite, VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { fromBase64Url, toBase64Url } from './encoding'
import type { CanonicalEnvelopeAad, EncodedSuitePayload } from './envelope'
import { getCryptoProvider } from './provider/active-provider'
import { wipe } from './sodium'
import type { MemberSecretV1 } from './vault-plaintext'
import {
  computeVaultKeyFingerprint,
  openKeyFromX25519Recipient,
  sealKeyToX25519Recipient,
  VAULT_KEY_KIND,
  WRAPPER_PURPOSE,
  X25519_SEALED_BOX_V1,
  type X25519WrapperContext,
} from './x25519-wrapper'

export const SCRIPT_EXECUTION_CONTRACT_VERSION = 1 as const
export const SCRIPT_EXECUTION_RESULT_MAX_UTF8_BYTES = 65_536
export const SCRIPT_EXECUTION_PARAMETER_MAX_COUNT = 32
export const SCRIPT_EXECUTION_REFERENCE_MAX_COUNT = 64
export const SCRIPT_EXECUTION_PACKAGE_MAX_BYTES = 2_097_152

const uuid = z.string().uuid()
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/)
const normalizedString = z.string().refine((value) => value === value.normalize('NFC'), 'String must be NFC')
const parameterName = normalizedString.regex(/^[A-Za-z_][A-Za-z0-9_]*$/).max(64)

const RESERVED_REFERENCE_ENV_NAMES = new Set([
  'BASHOPTS', 'BASH_ENV', 'CDPATH', 'ENV', 'GCONV_PATH', 'GLOBIGNORE', 'HOME', 'HOSTALIASES',
  'IFS', 'LD_PRELOAD', 'LOCPATH', 'LOGNAME', 'NLSPATH', 'NODE_OPTIONS', 'NODE_PATH', 'PATH',
  'PERL5LIB', 'PERL5OPT', 'PYTHONHOME', 'PYTHONINSPECT', 'PYTHONPATH', 'PYTHONSTARTUP', 'RUBYOPT',
  'SHELL', 'SHELLOPTS', 'TEMP', 'TMP', 'TMPDIR', 'USER',
])
const RESERVED_REFERENCE_ENV_PREFIXES = ['CLAW_', 'DYLD_', 'LD_', 'PALLADIN_'] as const
const jsonScalar = z.union([normalizedString.max(8192), z.number().finite(), z.boolean()])

const stringParameter = z.object({
  name: parameterName,
  description: normalizedString.min(1).max(1024),
  type: z.literal('string'),
  required: z.boolean(),
  minLength: z.number().int().min(0).max(8192).optional(),
  maxLength: z.number().int().min(0).max(8192).optional(),
  enum: z.array(normalizedString.max(8192)).min(1).max(128).optional(),
}).strict()

const integerParameter = z.object({
  name: parameterName,
  description: normalizedString.min(1).max(1024),
  type: z.literal('integer'),
  required: z.boolean(),
  minimum: z.number().safe().optional(),
  maximum: z.number().safe().optional(),
  enum: z.array(z.number().safe()).min(1).max(128).optional(),
}).strict()

const numberParameter = z.object({
  name: parameterName,
  description: normalizedString.min(1).max(1024),
  type: z.literal('number'),
  required: z.boolean(),
  minimum: z.number().finite().optional(),
  maximum: z.number().finite().optional(),
  enum: z.array(z.number().finite()).min(1).max(128).optional(),
}).strict()

const booleanParameter = z.object({
  name: parameterName,
  description: normalizedString.min(1).max(1024),
  type: z.literal('boolean'),
  required: z.boolean(),
  enum: z.array(z.boolean()).min(1).max(2).optional(),
}).strict()

export const scriptParameterDefinitionSchema = z.discriminatedUnion('type', [
  stringParameter,
  integerParameter,
  numberParameter,
  booleanParameter,
])

export const scriptExecutionMetadataSchema = z.object({
  contractVersion: z.literal(SCRIPT_EXECUTION_CONTRACT_VERSION),
  description: normalizedString.trim().min(1).max(4096),
  parameters: z.array(scriptParameterDefinitionSchema).max(SCRIPT_EXECUTION_PARAMETER_MAX_COUNT),
  returnResultToAgent: z.boolean().optional(),
}).strict()

const referenceSchema = z.object({
  env: parameterName,
  vaultId: uuid,
  entryId: uuid,
  fieldId: normalizedString.min(1).max(128),
  entryRevision: revision,
}).strict()

const manifestSchema = z.object({
  schema: z.literal('palladin.script-execution-manifest.v1'),
  contractVersion: z.literal(SCRIPT_EXECUTION_CONTRACT_VERSION),
  organizationId: uuid,
  agentId: uuid,
  agentAccessEpoch: z.number().int().positive(),
  vaultId: uuid,
  scriptEntryId: uuid,
  scriptRevision: revision,
  description: normalizedString.trim().min(1).max(4096),
  parameters: z.array(scriptParameterDefinitionSchema).max(SCRIPT_EXECUTION_PARAMETER_MAX_COUNT),
  returnResultToAgent: z.boolean(),
  interpreter: z.enum(['bash', 'sh', 'node', 'python']),
  scriptSource: normalizedString,
  references: z.array(referenceSchema).max(SCRIPT_EXECUTION_REFERENCE_MAX_COUNT),
}).strict()

const authorizationSchema = z.discriminatedUnion('source', [
  z.object({
    source: z.literal('scriptExecution'),
    grantId: uuid,
  }).strict(),
  z.object({
    source: z.literal('full'),
    grantId: uuid,
  }).strict(),
])

const packageScopeSchema = z.object({
  vaultId: uuid,
  entryId: uuid,
  fieldId: normalizedString.min(1).max(128),
  entryRevision: revision,
}).strict()

const packageBindingSchema = z.object({
  schema: z.literal('palladin.script-execution-package-binding.v1'),
  contractVersion: z.literal(SCRIPT_EXECUTION_CONTRACT_VERSION),
  organizationId: uuid,
  agentId: uuid,
  agentAccessEpoch: z.number().int().positive(),
  vaultId: uuid,
  scriptEntryId: uuid,
  scriptRevision: revision,
  manifestDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  authorization: authorizationSchema,
  scopes: z.array(packageScopeSchema).min(1).max(SCRIPT_EXECUTION_REFERENCE_MAX_COUNT + 1),
}).strict()

const transportScopeSchema = z.object({
  entryId: uuid,
  entryRevision: revision,
  isScript: z.boolean(),
}).strict()

const packageTransportBindingSchema = z.object({
  contractVersion: z.literal(SCRIPT_EXECUTION_CONTRACT_VERSION),
  organizationId: uuid,
  vaultId: uuid,
  grantId: uuid,
  agentId: uuid,
  agentAccessEpoch: z.number().int().positive(),
  scriptEntryId: uuid,
  scriptRevision: revision,
  packageRevision: revision,
  recipientAgentKeyVersion: z.number().int().positive(),
  recipientAgentKeyFingerprint: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  manifestDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  scopes: z.array(transportScopeSchema).min(1).max(SCRIPT_EXECUTION_REFERENCE_MAX_COUNT + 1),
}).strict()

const expectedPackageContextSchema = packageTransportBindingSchema.pick({
  organizationId: true,
  vaultId: true,
  agentId: true,
  agentAccessEpoch: true,
  scriptEntryId: true,
  scriptRevision: true,
  recipientAgentKeyVersion: true,
})

const encryptedReferenceEntrySchema = z.object({
  entryId: uuid,
  entryRevision: revision,
  encodedMemberSecret: z.string().min(1),
}).strict()

const encryptedPackagePayloadSchema = z.object({
  schema: z.literal('palladin.script-execution-package-payload.v1'),
  binding: packageBindingSchema,
  manifest: manifestSchema,
  entries: z.array(encryptedReferenceEntrySchema).max(SCRIPT_EXECUTION_REFERENCE_MAX_COUNT),
}).strict()

const encryptedPackageContainerSchema = z.object({
  schema: z.literal('palladin.script-execution-package-ciphertext.v1'),
  contractVersion: z.literal(SCRIPT_EXECUTION_CONTRACT_VERSION),
  packageRevision: revision,
  encodedSealedPackageDek: z.string().regex(/^[A-Za-z0-9_-]+$/),
  encodedSuitePayload: z.string().regex(/^[A-Za-z0-9_-]+$/),
}).strict()

export type ScriptParameterDefinition = z.infer<typeof scriptParameterDefinitionSchema>
export type ScriptExecutionMetadataV1 = z.infer<typeof scriptExecutionMetadataSchema>
export type ScriptExecutionReferenceV1 = z.infer<typeof referenceSchema>
export type ScriptExecutionManifestV1 = z.infer<typeof manifestSchema>
export type ScriptExecutionAuthorizationV1 = z.infer<typeof authorizationSchema>
export type ScriptExecutionPackageScopeV1 = z.infer<typeof packageScopeSchema>
export type ScriptExecutionPackageBindingV1 = z.infer<typeof packageBindingSchema>
export type ScriptExecutionPackageTransportScopeV1 = z.infer<typeof transportScopeSchema>
export type ScriptExecutionPackageTransportBindingV1 = z.infer<typeof packageTransportBindingSchema>
export type ScriptExecutionPackageExpectedContextV1 = z.infer<typeof expectedPackageContextSchema>
export type ScriptExecutionParameterValues = Readonly<Record<string, string | number | boolean>>

export interface ScriptExecutionPackageReferenceInput {
  entryId: string
  entryRevision: string
  encodedMemberSecret: Uint8Array
}

export interface ScriptExecutionEncryptedPackageV1 extends ScriptExecutionPackageTransportBindingV1 {
  encodedPackageCiphertext: string
}

export interface OpenedScriptExecutionReferenceV1 {
  entryId: string
  entryRevision: string
  encodedMemberSecret: Uint8Array
}

export interface OpenedScriptExecutionPackageV1 {
  binding: ScriptExecutionPackageBindingV1
  manifest: ScriptExecutionManifestV1
  entries: OpenedScriptExecutionReferenceV1[]
}

export interface SealScriptExecutionPackageInput {
  manifest: ScriptExecutionManifestV1
  grantId: string
  packageRevision: string
  recipientAgentKeyVersion: number
  recipientAgentPublicKey: Uint8Array
  entries: readonly ScriptExecutionPackageReferenceInput[]
}

export interface BuildScriptExecutionManifestInput {
  organizationId: string
  agentId: string
  agentAccessEpoch: number
  vaultId: string
  scriptEntryId: string
  scriptRevision: string
  memberSecret: MemberSecretV1
  referenceRevisions: Readonly<Record<string, string>>
}

export function effectiveReturnResultToAgent(metadata: Pick<ScriptExecutionMetadataV1, 'returnResultToAgent'> | undefined): boolean {
  return metadata?.returnResultToAgent === true
}

export function buildScriptExecutionManifest(input: BuildScriptExecutionManifestInput): ScriptExecutionManifestV1 {
  if (input.memberSecret.entryType !== 'script') throw new Error('Entry is not a Script')
  const metadata = input.memberSecret.content.execution
  if (!metadata) throw new Error('Script execution metadata is missing')
  const parsedMetadata = parseMetadata(metadata)
  const parameters = sortedUnique(parsedMetadata.parameters, (item) => item.name, 'Script parameter names')
  validateParameterDefinitions(parameters)
  const references = sortedUnique(input.memberSecret.content.refs.map((reference) => {
    if (reference.vaultId !== input.vaultId) throw new Error('Cross-Vault Script references are forbidden')
    const revision = input.referenceRevisions[reference.entryId]
    if (revision === undefined) throw new Error('A Script reference revision is missing')
    return { ...reference, entryRevision: revision }
  }), referenceKey, 'Script references')
  validateReferenceEnvironmentNames(references)
  return manifestSchema.parse({
    schema: 'palladin.script-execution-manifest.v1',
    contractVersion: SCRIPT_EXECUTION_CONTRACT_VERSION,
    organizationId: input.organizationId,
    agentId: input.agentId,
    agentAccessEpoch: input.agentAccessEpoch,
    vaultId: input.vaultId,
    scriptEntryId: input.scriptEntryId,
    scriptRevision: input.scriptRevision,
    description: parsedMetadata.description,
    parameters,
    returnResultToAgent: effectiveReturnResultToAgent(parsedMetadata),
    interpreter: input.memberSecret.content.interpreter,
    scriptSource: input.memberSecret.content.source,
    references,
  })
}

export function encodeScriptExecutionManifest(value: ScriptExecutionManifestV1): Uint8Array {
  const parsed = normalizeManifest(value)
  return new TextEncoder().encode(canonicalJson(parsed))
}

export function parseScriptExecutionManifest(bytes: Uint8Array): ScriptExecutionManifestV1 {
  const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  rejectDuplicateKeys(json)
  return normalizeManifest(JSON.parse(json))
}

export async function scriptExecutionManifestDigest(value: ScriptExecutionManifestV1): Promise<string> {
  const manifest = encodeScriptExecutionManifest(value)
  const domain = new TextEncoder().encode('PLDNSCRIPT1')
  const input = new Uint8Array(domain.length + manifest.length)
  input.set(domain)
  input.set(manifest, domain.length)
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input))
    return base64Url(digest)
  } finally {
    manifest.fill(0)
    input.fill(0)
  }
}

export function scriptExecutionDiscovery(manifest: ScriptExecutionManifestV1): ScriptExecutionMetadataV1 {
  const parsed = normalizeManifest(manifest)
  return {
    contractVersion: SCRIPT_EXECUTION_CONTRACT_VERSION,
    description: parsed.description,
    parameters: parsed.parameters,
    returnResultToAgent: parsed.returnResultToAgent,
  }
}

export function validateScriptExecutionParameters(
  definitions: readonly ScriptParameterDefinition[],
  values: unknown,
): ScriptExecutionParameterValues {
  const parsedDefinitions = sortedUnique(
    z.array(scriptParameterDefinitionSchema).max(SCRIPT_EXECUTION_PARAMETER_MAX_COUNT).parse(definitions),
    (item) => item.name,
    'Script parameter names',
  )
  validateParameterDefinitions(parsedDefinitions)
  if (!isRecord(values)) throw new Error('Script parameters must be an object')
  const known = new Map(parsedDefinitions.map((definition) => [definition.name, definition]))
  for (const name of Object.keys(values)) {
    if (!known.has(name)) throw new Error('Script parameters contain an undeclared name')
  }
  const validated: Record<string, string | number | boolean> = {}
  for (const definition of parsedDefinitions) {
    if (!Object.hasOwn(values, definition.name)) {
      if (definition.required) throw new Error('A required Script parameter is missing')
      continue
    }
    const value = values[definition.name]
    validateParameterValue(definition, value)
    validated[definition.name] = jsonScalar.parse(value)
  }
  const canonical = canonicalJson(validated)
  if (new TextEncoder().encode(canonical).length > 32_768) throw new Error('Script parameters exceed the request limit')
  return validated
}

export function encodeScriptExecutionParameters(
  definitions: readonly ScriptParameterDefinition[],
  values: unknown,
): Uint8Array {
  return new TextEncoder().encode(canonicalJson(validateScriptExecutionParameters(definitions, values)))
}

export async function buildScriptExecutionPackageBinding(
  manifest: ScriptExecutionManifestV1,
  authorization: ScriptExecutionAuthorizationV1,
): Promise<ScriptExecutionPackageBindingV1> {
  const parsed = normalizeManifest(manifest)
  const scopes = sortedUnique([
    {
      vaultId: parsed.vaultId,
      entryId: parsed.scriptEntryId,
      fieldId: 'script.source',
      entryRevision: parsed.scriptRevision,
    },
    ...parsed.references.map(({ vaultId, entryId, fieldId, entryRevision }) => ({ vaultId, entryId, fieldId, entryRevision })),
  ], scopeKey, 'Script package scopes')
  return packageBindingSchema.parse({
    schema: 'palladin.script-execution-package-binding.v1',
    contractVersion: SCRIPT_EXECUTION_CONTRACT_VERSION,
    organizationId: parsed.organizationId,
    agentId: parsed.agentId,
    agentAccessEpoch: parsed.agentAccessEpoch,
    vaultId: parsed.vaultId,
    scriptEntryId: parsed.scriptEntryId,
    scriptRevision: parsed.scriptRevision,
    manifestDigest: await scriptExecutionManifestDigest(parsed),
    authorization,
    scopes,
  })
}

export async function assertScriptExecutionPackage(
  binding: ScriptExecutionPackageBindingV1,
  manifest: ScriptExecutionManifestV1,
  openedScopes: readonly ScriptExecutionPackageScopeV1[],
): Promise<void> {
  const parsedBinding = packageBindingSchema.parse(binding)
  const parsedManifest = normalizeManifest(manifest)
  if (parsedBinding.organizationId !== parsedManifest.organizationId
    || parsedBinding.agentId !== parsedManifest.agentId
    || parsedBinding.agentAccessEpoch !== parsedManifest.agentAccessEpoch
    || parsedBinding.vaultId !== parsedManifest.vaultId
    || parsedBinding.scriptEntryId !== parsedManifest.scriptEntryId
    || parsedBinding.scriptRevision !== parsedManifest.scriptRevision
    || parsedBinding.manifestDigest !== await scriptExecutionManifestDigest(parsedManifest)) {
    throw new Error('Script execution package binding does not match its manifest')
  }
  const reconstructed = await buildScriptExecutionPackageBinding(
    parsedManifest,
    parsedBinding.authorization,
  )
  if (canonicalJson(reconstructed) !== canonicalJson(parsedBinding)) {
    throw new Error('Script execution package binding does not match its manifest scopes')
  }
  const expected = sortedUnique(parsedBinding.scopes, scopeKey, 'Script package scopes')
  const actual = sortedUnique(
    z.array(packageScopeSchema).max(SCRIPT_EXECUTION_REFERENCE_MAX_COUNT + 1).parse(openedScopes),
    scopeKey,
    'Opened Script package scopes',
  )
  if (canonicalJson(expected) !== canonicalJson(actual)) {
    throw new Error('Script execution package scopes are incomplete or substituted')
  }
}

export async function sealScriptExecutionPackage(
  input: SealScriptExecutionPackageInput,
): Promise<ScriptExecutionEncryptedPackageV1> {
  const manifest = normalizeManifest(input.manifest)
  const authorization = authorizationSchema.parse({ source: 'scriptExecution', grantId: input.grantId })
  const binding = await buildScriptExecutionPackageBinding(manifest, authorization)
  const entries = normalizeReferenceInputs(input.entries)
  let recipientFingerprint: Uint8Array | undefined
  let plaintext: Uint8Array | undefined
  let packageDek: Uint8Array | undefined
  let aad: CanonicalEnvelopeAad | undefined
  let parentDescriptorHash: Uint8Array | undefined
  try {
    assertReferenceEntriesMatchManifest(manifest, entries)
    recipientFingerprint = await computeVaultKeyFingerprint(
      input.recipientAgentPublicKey,
      VAULT_KEY_KIND.agentX25519,
    )
    const transportBinding = normalizeTransportBinding({
      contractVersion: SCRIPT_EXECUTION_CONTRACT_VERSION,
      organizationId: manifest.organizationId,
      vaultId: manifest.vaultId,
      grantId: input.grantId,
      agentId: manifest.agentId,
      agentAccessEpoch: manifest.agentAccessEpoch,
      scriptEntryId: manifest.scriptEntryId,
      scriptRevision: manifest.scriptRevision,
      packageRevision: input.packageRevision,
      recipientAgentKeyVersion: input.recipientAgentKeyVersion,
      recipientAgentKeyFingerprint: toBase64Url(recipientFingerprint),
      manifestDigest: binding.manifestDigest,
      scopes: structuralScopes(binding),
    })
    plaintext = new TextEncoder().encode(canonicalJson({
      schema: 'palladin.script-execution-package-payload.v1',
      binding,
      manifest,
      entries: entries.map((entry) => ({
        entryId: entry.entryId,
        entryRevision: entry.entryRevision,
        encodedMemberSecret: toBase64Url(entry.encodedMemberSecret),
      })),
    }))
    if (plaintext.length > MAX_ENCODED_SUITE_PAYLOAD_BYTES - 40) {
      throw new RangeError('Script execution package plaintext exceeds the encrypted payload limit')
    }

    const provider = getCryptoProvider()
    await provider.ready()
    packageDek = provider.randomBytes(provider.secretboxKeyBytes())
    aad = transportAad(transportBinding)
    parentDescriptorHash = await hashWithDomain('PLDNSCRIPTAAD1', aad)
    const [suitePayload, sealedDek] = await Promise.all([
      requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1).seal({
        plaintext,
        key: packageDek,
        aad,
      }),
      sealKeyToX25519Recipient(
        packageDek,
        input.recipientAgentPublicKey,
        wrapperContext(transportBinding, recipientFingerprint, parentDescriptorHash),
      ),
    ])
    const containerBytes = new TextEncoder().encode(canonicalJson({
      schema: 'palladin.script-execution-package-ciphertext.v1',
      contractVersion: SCRIPT_EXECUTION_CONTRACT_VERSION,
      packageRevision: transportBinding.packageRevision,
      encodedSealedPackageDek: toBase64Url(sealedDek),
      encodedSuitePayload: toBase64Url(suitePayload),
    }))
    try {
      if (containerBytes.length > SCRIPT_EXECUTION_PACKAGE_MAX_BYTES) {
        throw new RangeError('Encoded Script execution package exceeds its transport limit')
      }
      return {
        ...transportBinding,
        encodedPackageCiphertext: toBase64Url(containerBytes),
      }
    } finally {
      wipe(containerBytes)
      wipe(sealedDek)
      wipe(suitePayload)
    }
  } finally {
    for (const entry of entries) wipe(entry.encodedMemberSecret)
    if (plaintext) wipe(plaintext)
    if (packageDek) wipe(packageDek)
    if (aad) wipe(aad)
    if (parentDescriptorHash) wipe(parentDescriptorHash)
    if (recipientFingerprint) wipe(recipientFingerprint)
  }
}

export async function openScriptExecutionPackage(
  encryptedPackage: ScriptExecutionEncryptedPackageV1,
  recipientAgentPrivateKey: Uint8Array,
  expectedContext: ScriptExecutionPackageExpectedContextV1,
): Promise<OpenedScriptExecutionPackageV1> {
  const { encodedPackageCiphertext, ...outer } = encryptedPackage
  const transportBinding = normalizeTransportBinding(outer)
  assertExpectedContextMatchesTransport(expectedContext, transportBinding)
  const provider = getCryptoProvider()
  await provider.ready()
  const recipientPublicKey = provider.scalarMultBase(recipientAgentPrivateKey)
  let recipientFingerprint: Uint8Array | undefined
  let containerBytes: Uint8Array | undefined
  let aad: CanonicalEnvelopeAad | undefined
  let parentDescriptorHash: Uint8Array | undefined
  let sealedDek: Uint8Array | undefined
  let suitePayload: EncodedSuitePayload | undefined
  let plaintext: Uint8Array | undefined
  let packageDek: Uint8Array | undefined
  let openedEntries: OpenedScriptExecutionReferenceV1[] | undefined
  let completed = false
  try {
    recipientFingerprint = await computeVaultKeyFingerprint(
      recipientPublicKey,
      VAULT_KEY_KIND.agentX25519,
    )
    if (toBase64Url(recipientFingerprint) !== transportBinding.recipientAgentKeyFingerprint) {
      throw new Error('Script execution package recipient does not match the Agent key')
    }

    containerBytes = fromBase64Url(encodedPackageCiphertext, SCRIPT_EXECUTION_PACKAGE_MAX_BYTES)
    const container = parseCanonicalJson(containerBytes, encryptedPackageContainerSchema)
    if (container.contractVersion !== transportBinding.contractVersion
      || container.packageRevision !== transportBinding.packageRevision) {
      throw new Error('Script execution ciphertext does not match its outer package revision')
    }
    aad = transportAad(transportBinding)
    parentDescriptorHash = await hashWithDomain('PLDNSCRIPTAAD1', aad)
    sealedDek = fromBase64Url(container.encodedSealedPackageDek, 120)
    suitePayload = fromBase64Url(
      container.encodedSuitePayload,
      MAX_ENCODED_SUITE_PAYLOAD_BYTES,
    ) as EncodedSuitePayload
    packageDek = await openKeyFromX25519Recipient(
      sealedDek,
      recipientPublicKey,
      recipientAgentPrivateKey,
      wrapperContext(transportBinding, recipientFingerprint, parentDescriptorHash),
    )
    plaintext = await requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1).open({
      payload: suitePayload,
      key: packageDek,
      aad,
    })
    const parsed = parseCanonicalJson(plaintext, encryptedPackagePayloadSchema)
    const manifest = normalizeManifest(parsed.manifest)
    await assertScriptExecutionPackage(parsed.binding, manifest, parsed.binding.scopes)
    openedEntries = parsed.entries.map((entry) => ({
      entryId: entry.entryId,
      entryRevision: entry.entryRevision,
      encodedMemberSecret: fromBase64Url(entry.encodedMemberSecret, MAX_ENCODED_SUITE_PAYLOAD_BYTES),
    }))
    assertReferenceEntriesMatchManifest(manifest, openedEntries)
    assertTransportMatchesPayload(transportBinding, parsed.binding, manifest)
    completed = true
    return { binding: parsed.binding, manifest, entries: openedEntries }
  } finally {
    wipe(recipientPublicKey)
    if (recipientFingerprint) wipe(recipientFingerprint)
    if (containerBytes) wipe(containerBytes)
    if (aad) wipe(aad)
    if (parentDescriptorHash) wipe(parentDescriptorHash)
    if (sealedDek) wipe(sealedDek)
    if (suitePayload) wipe(suitePayload)
    if (packageDek) wipe(packageDek)
    if (plaintext) wipe(plaintext)
    if (!completed && openedEntries) {
      for (const entry of openedEntries) wipe(entry.encodedMemberSecret)
    }
  }
}

export async function refreshScriptExecutionPackage(
  previous: ScriptExecutionEncryptedPackageV1,
  nextManifest: ScriptExecutionManifestV1,
  entries: readonly ScriptExecutionPackageReferenceInput[],
  recipientAgentPublicKey: Uint8Array,
): Promise<ScriptExecutionEncryptedPackageV1> {
  const current = normalizeTransportBinding(previous)
  const next = normalizeManifest(nextManifest)
  if (current.organizationId !== next.organizationId
    || current.agentId !== next.agentId
    || current.agentAccessEpoch !== next.agentAccessEpoch
    || current.vaultId !== next.vaultId
    || current.scriptEntryId !== next.scriptEntryId) {
    throw new Error('Script package refresh cannot change grant identity')
  }
  const packageRevision = BigInt(current.packageRevision)
  if (packageRevision >= 0xffffffffffffffffn) throw new RangeError('Script package revision is exhausted')
  return sealScriptExecutionPackage({
    manifest: next,
    grantId: current.grantId,
    packageRevision: String(packageRevision + 1n),
    recipientAgentKeyVersion: current.recipientAgentKeyVersion,
    recipientAgentPublicKey,
    entries,
  })
}

export async function refreshScriptExecutionPackageBinding(
  previous: ScriptExecutionPackageBindingV1,
  nextManifest: ScriptExecutionManifestV1,
): Promise<ScriptExecutionPackageBindingV1> {
  const parsed = packageBindingSchema.parse(previous)
  const next = normalizeManifest(nextManifest)
  if (parsed.authorization.source !== 'scriptExecution') {
    throw new Error('FULL grants do not carry per-Script package material')
  }
  if (parsed.organizationId !== next.organizationId
    || parsed.agentId !== next.agentId
    || parsed.agentAccessEpoch !== next.agentAccessEpoch
    || parsed.vaultId !== next.vaultId
    || parsed.scriptEntryId !== next.scriptEntryId) {
    throw new Error('Script package refresh cannot change grant identity')
  }
  return buildScriptExecutionPackageBinding(next, parsed.authorization)
}

function normalizeTransportBinding(value: unknown): ScriptExecutionPackageTransportBindingV1 {
  const candidate = isRecord(value) && Object.hasOwn(value, 'encodedPackageCiphertext')
    ? Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'encodedPackageCiphertext'))
    : value
  const parsed = packageTransportBindingSchema.parse(candidate)
  assertUInt64(parsed.scriptRevision, 'Script revision')
  assertUInt64(parsed.packageRevision, 'Package revision')
  const scopes = sortedUnique(parsed.scopes, (scope) => scope.entryId, 'Script transport scopes')
  for (const scope of scopes) assertUInt64(scope.entryRevision, 'Entry revision')
  if (scopes.filter((scope) => scope.isScript).length !== 1
    || scopes.find((scope) => scope.isScript)?.entryId !== parsed.scriptEntryId
    || scopes.find((scope) => scope.isScript)?.entryRevision !== parsed.scriptRevision) {
    throw new Error('Script transport scopes must identify exactly the current parent Script')
  }
  return { ...parsed, scopes }
}

function normalizeReferenceInputs(
  values: readonly ScriptExecutionPackageReferenceInput[],
): ScriptExecutionPackageReferenceInput[] {
  if (values.length > SCRIPT_EXECUTION_REFERENCE_MAX_COUNT) {
    throw new RangeError('Script execution package has too many referenced Entries')
  }
  const parsed = sortedUnique(values.map((entry) => {
    uuid.parse(entry.entryId)
    assertUInt64(entry.entryRevision, 'Reference Entry revision')
    if (!(entry.encodedMemberSecret instanceof Uint8Array)
      || entry.encodedMemberSecret.length === 0
      || entry.encodedMemberSecret.length > MAX_ENCODED_SUITE_PAYLOAD_BYTES) {
      throw new RangeError('Encoded referenced MemberSecret is invalid')
    }
    return {
      entryId: entry.entryId,
      entryRevision: entry.entryRevision,
      encodedMemberSecret: new Uint8Array(entry.encodedMemberSecret),
    }
  }), (entry) => entry.entryId, 'Script package referenced Entries')
  return parsed
}

function assertReferenceEntriesMatchManifest(
  manifest: ScriptExecutionManifestV1,
  entries: readonly Pick<ScriptExecutionPackageReferenceInput, 'entryId' | 'entryRevision'>[],
): void {
  const expected = new Map<string, string>()
  for (const reference of manifest.references) {
    const current = expected.get(reference.entryId)
    if (current !== undefined && current !== reference.entryRevision) {
      throw new Error('A referenced Entry cannot have conflicting revisions')
    }
    expected.set(reference.entryId, reference.entryRevision)
  }
  if (entries.length !== expected.size
    || entries.some((entry) => expected.get(entry.entryId) !== entry.entryRevision)) {
    throw new Error('Script package referenced Entries are incomplete, stale or substituted')
  }
}

function structuralScopes(
  binding: ScriptExecutionPackageBindingV1,
): ScriptExecutionPackageTransportScopeV1[] {
  const scopes = new Map<string, ScriptExecutionPackageTransportScopeV1>()
  for (const scope of binding.scopes) {
    const isScript = scope.entryId === binding.scriptEntryId
    const current = scopes.get(scope.entryId)
    if (current && (current.entryRevision !== scope.entryRevision || current.isScript !== isScript)) {
      throw new Error('Script package scopes contain conflicting structural coordinates')
    }
    scopes.set(scope.entryId, {
      entryId: scope.entryId,
      entryRevision: scope.entryRevision,
      isScript,
    })
  }
  return [...scopes.values()].sort((left, right) => compareUtf8(left.entryId, right.entryId))
}

function assertTransportMatchesPayload(
  transport: ScriptExecutionPackageTransportBindingV1,
  binding: ScriptExecutionPackageBindingV1,
  manifest: ScriptExecutionManifestV1,
): void {
  if (binding.authorization.source !== 'scriptExecution'
    || binding.authorization.grantId !== transport.grantId
    || transport.organizationId !== manifest.organizationId
    || transport.agentId !== manifest.agentId
    || transport.agentAccessEpoch !== manifest.agentAccessEpoch
    || transport.vaultId !== manifest.vaultId
    || transport.scriptEntryId !== manifest.scriptEntryId
    || transport.scriptRevision !== manifest.scriptRevision
    || transport.manifestDigest !== binding.manifestDigest
    || canonicalJson(transport.scopes) !== canonicalJson(structuralScopes(binding))) {
    throw new Error('Script package ciphertext does not match its structural transport binding')
  }
}

function assertExpectedContextMatchesTransport(
  value: ScriptExecutionPackageExpectedContextV1,
  transport: ScriptExecutionPackageTransportBindingV1,
): void {
  const expected = expectedPackageContextSchema.parse(value)
  assertUInt64(expected.scriptRevision, 'Expected Script revision')
  if (expected.organizationId !== transport.organizationId
    || expected.vaultId !== transport.vaultId
    || expected.agentId !== transport.agentId
    || expected.agentAccessEpoch !== transport.agentAccessEpoch
    || expected.scriptEntryId !== transport.scriptEntryId
    || expected.scriptRevision !== transport.scriptRevision
    || expected.recipientAgentKeyVersion !== transport.recipientAgentKeyVersion) {
    throw new Error('Script execution package does not match the requested execution context')
  }
}

function transportAad(binding: ScriptExecutionPackageTransportBindingV1): CanonicalEnvelopeAad {
  return new TextEncoder().encode(canonicalJson(normalizeTransportBinding(binding))) as CanonicalEnvelopeAad
}

function wrapperContext(
  binding: ScriptExecutionPackageTransportBindingV1,
  recipientFingerprint: Uint8Array,
  parentDescriptorHash: Uint8Array,
): X25519WrapperContext {
  return {
    protocolVersion: 2,
    wrapperSuiteId: X25519_SEALED_BOX_V1,
    purpose: WRAPPER_PURPOSE.scriptExecutionDek,
    organizationId: binding.organizationId,
    vaultId: binding.vaultId,
    entryId: binding.scriptEntryId,
    grantOrRequestId: binding.grantId,
    agentId: binding.agentId,
    resourceRevision: BigInt(binding.packageRevision),
    wrappedKeyVersion: 1,
    recipientKeyKind: VAULT_KEY_KIND.agentX25519,
    recipientKeyVersion: binding.recipientAgentKeyVersion,
    recipientFingerprint,
    parentDescriptorHash,
  }
}

async function hashWithDomain(domain: string, bytes: Uint8Array): Promise<Uint8Array> {
  const prefix = new TextEncoder().encode(domain)
  const input = new Uint8Array(prefix.length + bytes.length)
  input.set(prefix)
  input.set(bytes, prefix.length)
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', input))
  } finally {
    wipe(prefix)
    wipe(input)
  }
}

function parseCanonicalJson<T>(bytes: Uint8Array, schema: z.ZodType<T>): T {
  const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  rejectDuplicateKeys(json)
  const parsed = schema.parse(JSON.parse(json))
  if (canonicalJson(parsed) !== json) throw new Error('Script execution package JSON is not canonical')
  return parsed
}

function assertUInt64(value: string, label: string): void {
  if (!/^[1-9][0-9]*$/.test(value) || BigInt(value) > 0xffffffffffffffffn) {
    throw new RangeError(`${label} must be a positive UInt64 canonical decimal`)
  }
}

function normalizeManifest(value: unknown): ScriptExecutionManifestV1 {
  const parsed = manifestSchema.parse(value)
  assertUInt64(parsed.scriptRevision, 'Script revision')
  for (const reference of parsed.references) {
    assertUInt64(reference.entryRevision, 'Reference Entry revision')
    if (reference.entryId === parsed.scriptEntryId) {
      throw new Error('A Script cannot reference its own Entry')
    }
  }
  const parameters = sortedUnique(parsed.parameters, (item) => item.name, 'Script parameter names')
  validateParameterDefinitions(parameters)
  const references = sortedUnique(parsed.references, referenceKey, 'Script references')
  validateReferenceEnvironmentNames(references)
  return { ...parsed, parameters, references }
}

export function isAllowedScriptReferenceEnvName(value: string): boolean {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value) || new TextEncoder().encode(value).length > 64) return false
  const normalized = value.toUpperCase()
  return !RESERVED_REFERENCE_ENV_NAMES.has(normalized)
    && !RESERVED_REFERENCE_ENV_PREFIXES.some((prefix) => normalized.startsWith(prefix))
}

function validateReferenceEnvironmentNames(references: readonly ScriptExecutionReferenceV1[]): void {
  const names = new Set<string>()
  for (const reference of references) {
    const normalized = reference.env.toUpperCase()
    if (!isAllowedScriptReferenceEnvName(reference.env)) {
      throw new Error('Script reference environment name is reserved or invalid')
    }
    if (names.has(normalized)) throw new Error('Script reference environment names must be unique')
    names.add(normalized)
  }
}

function parseMetadata(value: unknown): ScriptExecutionMetadataV1 {
  const parsed = scriptExecutionMetadataSchema.parse(value)
  return { ...parsed, description: parsed.description.trim() }
}

function validateParameterDefinitions(definitions: readonly ScriptParameterDefinition[]): void {
  for (const definition of definitions) {
    if ('minimum' in definition && 'maximum' in definition
      && definition.minimum !== undefined && definition.maximum !== undefined
      && definition.minimum > definition.maximum) {
      throw new Error('Script parameter minimum exceeds maximum')
    }
    if (definition.type === 'string'
      && definition.minLength !== undefined && definition.maxLength !== undefined
      && definition.minLength > definition.maxLength) {
      throw new Error('Script parameter minLength exceeds maxLength')
    }
    if (definition.enum && new Set(definition.enum.map((value) => canonicalJson(value))).size !== definition.enum.length) {
      throw new Error('Script parameter enum values must be unique')
    }
    if (definition.enum) {
      for (const value of definition.enum) validateParameterValue({ ...definition, enum: undefined }, value)
    }
  }
}

function validateParameterValue(definition: ScriptParameterDefinition, value: unknown): void {
  if (definition.type === 'string') {
    if (typeof value !== 'string' || value !== value.normalize('NFC')) throw new Error('Script parameter type is invalid')
    const length = [...value].length
    if (definition.minLength !== undefined && length < definition.minLength) throw new Error('Script parameter is below minLength')
    if (definition.maxLength !== undefined && length > definition.maxLength) throw new Error('Script parameter exceeds maxLength')
  } else if (definition.type === 'integer') {
    if (!Number.isSafeInteger(value)) throw new Error('Script parameter type is invalid')
  } else if (definition.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('Script parameter type is invalid')
  } else if (typeof value !== 'boolean') {
    throw new Error('Script parameter type is invalid')
  }
  if ('minimum' in definition && definition.minimum !== undefined && (value as number) < definition.minimum) {
    throw new Error('Script parameter is below minimum')
  }
  if ('maximum' in definition && definition.maximum !== undefined && (value as number) > definition.maximum) {
    throw new Error('Script parameter exceeds maximum')
  }
  if (definition.enum && !definition.enum.some((allowed) => Object.is(allowed, value))) {
    throw new Error('Script parameter is outside its enum')
  }
}

function sortedUnique<T>(values: readonly T[], key: (value: T) => string, label: string): T[] {
  const sorted = [...values].sort((left, right) => compareUtf8(key(left), key(right)))
  for (let index = 1; index < sorted.length; index += 1) {
    if (key(sorted[index - 1]) === key(sorted[index])) throw new Error(`${label} must be unique`)
  }
  return sorted
}

function referenceKey(reference: Pick<ScriptExecutionReferenceV1, 'env' | 'entryId' | 'fieldId'>): string {
  return `${reference.env}\u0000${reference.entryId}\u0000${reference.fieldId}`
}

function scopeKey(scope: ScriptExecutionPackageScopeV1): string {
  return `${scope.vaultId}\u0000${scope.entryId}\u0000${scope.fieldId}`
}

function compareUtf8(left: string, right: string): number {
  const leftBytes = new TextEncoder().encode(left.normalize('NFC'))
  const rightBytes = new TextEncoder().encode(right.normalize('NFC'))
  const limit = Math.min(leftBytes.length, rightBytes.length)
  for (let index = 0; index < limit; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index]
  }
  return leftBytes.length - rightBytes.length
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Canonical Script JSON requires finite numbers')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
  }
  throw new TypeError('Unsupported canonical Script JSON value')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function base64Url(value: Uint8Array): string {
  let binary = ''
  for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function rejectDuplicateKeys(json: string): void {
  let index = 0
  const whitespace = () => { while (/\s/.test(json[index] ?? '')) index += 1 }
  const readString = (): string => {
    const start = index++
    while (index < json.length) {
      if (json[index] === '\\') index += 2
      else if (json[index++] === '"') return JSON.parse(json.slice(start, index)) as string
    }
    throw new SyntaxError('Unterminated JSON string')
  }
  const readValue = (): void => {
    whitespace()
    if (json[index] === '{') {
      index += 1; whitespace(); const keys = new Set<string>()
      if (json[index] === '}') { index += 1; return }
      while (true) {
        whitespace(); if (json[index] !== '"') throw new SyntaxError('Object key expected')
        const key = readString(); if (keys.has(key)) throw new SyntaxError(`Duplicate JSON property: ${key}`); keys.add(key)
        whitespace(); if (json[index++] !== ':') throw new SyntaxError('Colon expected'); readValue(); whitespace()
        if (json[index] === '}') { index += 1; return }
        if (json[index++] !== ',') throw new SyntaxError('Comma expected')
      }
    }
    if (json[index] === '[') {
      index += 1; whitespace(); if (json[index] === ']') { index += 1; return }
      while (true) { readValue(); whitespace(); if (json[index] === ']') { index += 1; return }; if (json[index++] !== ',') throw new SyntaxError('Comma expected') }
    }
    if (json[index] === '"') { readString(); return }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(json.slice(index))
    if (!match) throw new SyntaxError('Invalid JSON value')
    index += match[0].length
  }
  readValue(); whitespace(); if (index !== json.length) throw new SyntaxError('Trailing JSON data')
}
