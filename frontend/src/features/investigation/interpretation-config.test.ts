import { describe, expect, it } from 'vitest'
import { sampleModel, modelSignature, replaceFraming, formatModel } from './interpretation-config'
const framing = { schema_version: 'framing-1' as const, start: 0, rule: { kind: 'length' as const, width: 2 as const, endian: 'big' as const, offset: 0, multiplier: 1, adjustment: 2 }, max_message_bytes: 1048576, max_pieces: 200000 }
describe('interpretation editor documents', () => {
  it('derives payload length independently of TCP packet boundaries', () => {
    const model = JSON.parse(sampleModel(framing, 'length'))
    expect(model.fields[1].length).toEqual({ field: 'payload_length', multiplier: 1, add: 0 })
    expect(model.framing).toEqual(framing)
  })
  it('preserves exact 64-bit numbers during formatting and framing edits', () => {
    const text = sampleModel(framing).replace('"checks": []', '"checks": [], "integer": 18446744073709551615, "negative": -9223372036854775808')
    const changed = replaceFraming(text, { ...framing, start: 3 })
    expect(changed).toContain('18446744073709551615')
    expect(changed).toContain('-9223372036854775808')
    expect(formatModel(text)).toContain('18446744073709551615')
    expect(modelSignature(text)).not.toBe(modelSignature(text.replace('18446744073709551615', '18446744073709551614')))
  })
  it('compares key order without changing strings that contain numbers', () => {
    expect(modelSignature('{"name":"test 123", "n":2}')).toBe(modelSignature('{"n":2,"name":"test 123"}'))
    expect(formatModel('{"name":"test \\"123\\""}')).toContain('test \\"123\\"')
  })
})
