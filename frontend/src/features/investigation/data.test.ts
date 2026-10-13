import { describe, expect, it } from 'vitest'
import { ascii, cells, diff, token, utcInput, type Bytes } from './data'

describe('HEX evidence and comparison', () => {
  it('keeps gaps and conflict alternatives separate from real zero bytes', () => {
    const data = { blocks: [
      { byte_range: { start: 0, end: 2 }, status: 'known', variants: [{ data_hex: '0041', sources: [] }] },
      { byte_range: { start: 2, end: 3 }, status: 'ambiguous', variants: [{ data_hex: '42', sources: [] }, { data_hex: '43', sources: [] }] },
      { byte_range: { start: 3, end: 5 }, status: 'gap', variants: [] },
    ] } as unknown as Bytes
    const map = cells(data)
    expect(token(map.get(0))).toBe('00')
    expect(ascii(map.get(1))).toBe('A')
    expect(token(map.get(2))).toBe('??')
    expect(map.get(2)?.values).toEqual(['42', '43'])
    expect(token(map.get(3))).toBe('—')
    expect(map.get(3)?.values).toEqual([])
  })
  it('does not treat matching unknown bytes or differing lengths as equal', () => {
    const a = { status: 'known', values: ['41'] }
    expect(diff(a, a)).toBe('equal')
    expect(diff(a, { status: 'known', values: ['42'] })).toBe('different')
    expect(diff({ status: 'gap', values: [] }, { status: 'gap', values: [] })).toBe('unknown')
    expect(diff(a, undefined)).toBe('unknown')
    expect(diff(a, { status: 'ambiguous', values: ['41','42'] })).toBe('unknown')
  })
  it('treats UTC filter input independently of the browser timezone', () => {
    expect(utcInput('2023-11-14T22:13')).toBe('1699999980000000000')
    expect(() => utcInput('bad')).toThrow()
  })
})
