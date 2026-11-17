// The token schema validator is generated at build time
// (scripts/build-validator.mjs) and committed. This test fails when the
// committed file no longer matches what the generator produces from the
// current schema, for example after an edit to token.schema.json without
// re-running `npm run build:validator`.

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
// @ts-expect-error: plain ESM build script without type declarations
import { generate, OUTPUT_PATH } from '../../scripts/build-validator.mjs'

describe('generated token schema validator', () => {
  it('matches the generator output for the current schema', () => {
    const committed = readFileSync(OUTPUT_PATH as string, 'utf8')
    expect(committed).toBe((generate as () => string)())
  })

  it('is written to src/schema/validator.generated.js', () => {
    expect(OUTPUT_PATH).toBe(resolve(__dirname, '../../src/schema/validator.generated.js'))
  })
})
