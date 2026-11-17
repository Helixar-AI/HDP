// Generates src/schema/validator.generated.js from src/schema/token.schema.json.
//
// Ajv normally compiles a schema at runtime with `new Function`. Runtimes that
// forbid code generation from strings (Cloudflare Workers, strict
// Content-Security-Policy pages, Node with --disallow-code-generation-from-strings)
// then fail when the package loads. Ajv's standalone mode emits the compiled
// validator as source code instead, so it is compiled once here, at build
// time, and shipped as ordinary JavaScript.
//
// Usage:
//   node scripts/build-validator.mjs           write the generated file
//   import { generate } from './build-validator.mjs'   return the text only

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import standaloneCode from 'ajv/dist/standalone/index.js'

const here = dirname(fileURLToPath(import.meta.url))
export const SCHEMA_PATH = resolve(here, '../src/schema/token.schema.json')
export const OUTPUT_PATH = resolve(here, '../src/schema/validator.generated.js')

export function generate() {
  const schemaText = readFileSync(SCHEMA_PATH, 'utf8')
  const schema = JSON.parse(schemaText)
  const sha256 = createHash('sha256').update(schemaText).digest('hex')

  // Same options as the former runtime compile (strict: false), plus source
  // generation. ESM output so the bundler can emit both the CommonJS and the
  // ES module builds from one import graph.
  const ajv = new Ajv2020({ strict: false, code: { source: true, esm: true } })
  addFormats(ajv)
  const validate = ajv.compile(schema)
  const body = standaloneCode(ajv, validate)

  return (
    '// GENERATED FILE. Do not edit by hand.\n' +
    '// Source: src/schema/token.schema.json (sha256 ' + sha256 + ')\n' +
    '// Generator: scripts/build-validator.mjs (Ajv standalone code).\n' +
    '/* eslint-disable */\n' +
    body +
    '\n'
  )
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(OUTPUT_PATH, generate())
  console.log('wrote ' + OUTPUT_PATH)
}
