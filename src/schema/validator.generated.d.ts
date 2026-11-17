// Type declaration for the generated validator (scripts/build-validator.mjs).
// Hand-written: Ajv's standalone output is plain JavaScript without types.

export interface ValidationError {
  instancePath: string
  schemaPath: string
  keyword: string
  params: Record<string, unknown>
  message?: string
}

export interface ValidateFunction {
  (data: unknown): boolean
  errors?: ValidationError[] | null
}

export declare const validate: ValidateFunction
declare const _default: ValidateFunction
export default _default
