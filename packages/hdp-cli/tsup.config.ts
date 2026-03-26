import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  splitting: false,
  noExternal: ['@helixar/hdp'],
  banner: {
    js: '#!/usr/bin/env node',
  },
})
