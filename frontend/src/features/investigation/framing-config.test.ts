import { expect, test } from 'vitest'
import { framingSignature, framingSpec, initialFraming } from './framing-config'

test('manual boundaries are explicit, ordered and within extent', () => {
  const spec = framingSpec({ ...initialFraming, kind: 'manual', start: '9', ranges: '0:5\n5:10' }, 10)
  expect(spec.start).toBe(0)
  expect(spec.rule).toEqual({ kind: 'manual', ranges: [{ start: 0, end: 5 }, { start: 5, end: 10 }] })
  expect(() => framingSpec({ ...initialFraming, kind: 'manual', ranges: '0:5\n4:10' }, 10)).toThrow()
  expect(() => framingSpec({ ...initialFraming, kind: 'manual', ranges: '0:11' }, 10)).toThrow()
})
test('length formula uses validated integers and marker hex preserves full bytes', () => {
  expect(framingSpec({ ...initialFraming, kind: 'length', width: '1', multiplier: '2', adjustment: '-1' }, 10).rule).toMatchObject({ kind: 'length', width: 1, multiplier: 2, adjustment: -1 })
  expect(framingSpec({ ...initialFraming, kind: 'markers', startHex: 'AA BB', endHex: 'Cc' }, 10).rule).toEqual({ kind: 'markers', start_hex: 'aabb', end_hex: 'cc' })
  expect(() => framingSpec({ ...initialFraming, kind: 'length', multiplier: '1.5' }, 10)).toThrow()
  expect(() => framingSpec({ ...initialFraming, kind: 'markers', startHex: 'A', endHex: 'CC' }, 10)).toThrow()
  expect(() => framingSpec({ ...initialFraming, size: '0' }, 10)).toThrow()
})
test('saved configuration comparison ignores object key order', () => {
  const spec = framingSpec(initialFraming, 10)
  const { rule, ...rest } = spec
  const reordered = { rule, ...rest }
  expect(framingSignature(spec)).toBe(framingSignature(reordered))
  expect(framingSignature(spec)).not.toBe(framingSignature(framingSpec({ ...initialFraming, size: '7' }, 10)))
})
