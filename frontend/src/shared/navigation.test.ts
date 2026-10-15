import { expect, test } from 'vitest'
import { sectionFromHash, sections } from './navigation'

test('all project sections have stable URLs and unknown URLs fall back to data', () => {
  for (const section of sections) expect(sectionFromHash(`#${section}`)).toBe(section)
  expect(sectionFromHash('')).toBe('data')
  expect(sectionFromHash('#not-a-section')).toBe('data')
})
