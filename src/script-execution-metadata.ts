import { z } from 'zod'

export const SCRIPT_EXECUTION_CONTRACT_VERSION = 1 as const
export const SCRIPT_EXECUTION_PARAMETER_MAX_COUNT = 32

const normalizedString = z.string().refine((value) => value === value.normalize('NFC'), 'String must be NFC')
const parameterName = normalizedString.regex(/^[A-Za-z_][A-Za-z0-9_]*$/).max(64)

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

export type ScriptParameterDefinition = z.infer<typeof scriptParameterDefinitionSchema>
export type ScriptExecutionMetadataV1 = z.infer<typeof scriptExecutionMetadataSchema>
