import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  splitting: false,
  noExternal: ['@helixar_ai/hdp'],
  banner: {
    js: '#!/usr/bin/env node',
  },
})
