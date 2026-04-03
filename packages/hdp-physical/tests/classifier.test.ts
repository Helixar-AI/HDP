// packages/hdp-physical/tests/classifier.test.ts
import { describe, it, expect } from 'vitest'
import { IrreversibilityClassifier } from '../src/classifier/index.js'
import samples from './vectors/action-class-samples.json'

const classifier = new IrreversibilityClassifier()

describe('IrreversibilityClassifier — test vectors', () => {
  for (const sample of samples) {
    it(`classifies "${sample.label}" as Class ${sample.expected_class}`, () => {
      const result = classifier.classify({
        description: sample.description,
        force_n: (sample as Record<string, unknown>).force_n as number | undefined,
        velocity_ms: (sample as Record<string, unknown>).velocity_ms as number | undefined,
      })
      expect(result.action_class).toBe(sample.expected_class)
    })
  }
})

describe('IrreversibilityClassifier — reasoning', () => {
  it('returns a non-empty reason string', () => {
    const result = classifier.classify({ description: 'pick box' })
    expect(result.reason.length).toBeGreaterThan(0)
    expect(result.triggered_rule.length).toBeGreaterThan(0)
  })
})
