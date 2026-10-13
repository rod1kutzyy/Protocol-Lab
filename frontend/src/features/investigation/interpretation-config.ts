import type { components } from '@/shared/api-types'
type Framing = components['schemas']['FramingSpec']
export function sampleModel(framing: Framing, preset: 'raw' | 'length' | 'variants' = 'raw') {
  const integer = (name: string, width = 1, signed = false, endian = 'big') => ({ kind: 'int', name, width, signed, endian })
  let fields: unknown[] = [{ kind: 'bytes', name: 'raw', length: 'remaining' }]
  if (preset === 'length') {
    const rule = framing.rule
    if (rule.kind !== 'length') throw new Error('Пример поля длины требует соответствующего режима фрейминга')
    fields = [
      ...(rule.offset ? [{ kind: 'bytes', name: 'prefix', length: rule.offset }] : []),
      integer('payload_length', rule.width, false, rule.endian),
      { kind: 'bytes', name: 'payload', length: { field: 'payload_length', multiplier: rule.multiplier, add: rule.adjustment - rule.offset - rule.width } },
    ]
  } else if (preset === 'variants') {
    fields = [integer('count'), { kind: 'array', name: 'entries', count: { field: 'count' }, fields: [
      integer('tag'), { kind: 'switch', name: 'body', selector: 'tag', cases: {
        '1': [integer('value', 2, true, 'little')], '2': [{ kind: 'bytes', name: 'raw', length: 2 }],
      } },
    ] }]
  }
  return JSON.stringify({ schema_version: 'interpretation-1', name: 'Исследуемый протокол', framing, fields, checks: [], max_array_items: 1024, max_decoded_fields: 4096 }, null, 2)
}
// Preserve JSON integer tokens before JavaScript's Number parser can round them.
// This private marker cannot be a valid model field/property in interpretation-1.
function exactJson(text: string) {
  const tokens = text.replace(/("(?:[^"\\]|\\.)*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/g, token => token.startsWith('"') ? token : JSON.stringify({ __pl_numeric_token__: token }))
  return JSON.parse(tokens)
}
function renderExact(value: unknown) {
  return JSON.stringify(value, null, 2).replace(/\{\n\s*"__pl_numeric_token__": "([-\d.eE+]+)"\n\s*\}/g, '$1')
}
export function formatModel(text: string) { return renderExact(exactJson(text)) }
export function replaceFraming(text: string, framing: Framing) {
  const document = exactJson(text)
  document.framing = exactJson(JSON.stringify(framing))
  return renderExact(document)
}
export function modelSignature(text: string) {
  const sorted = (v: unknown): unknown => Array.isArray(v) ? v.map(sorted) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)).map(([k, value]) => [k, sorted(value)])) : v
  return JSON.stringify(sorted(exactJson(text)))
}
