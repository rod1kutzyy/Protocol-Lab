import type { components } from '@/shared/api-types'
export type FramingSpec = components['schemas']['FramingSpec']
export type FramingDraft = {
  kind: 'manual' | 'fixed' | 'length' | 'markers'; start: string; size: string
  ranges: string; offset: string; width: string; endian: 'big' | 'little'
  multiplier: string; adjustment: string; startHex: string; endHex: string; maxBytes: string
}
export const initialFraming: FramingDraft = {
  kind: 'fixed', start: '0', size: '5', ranges: '', offset: '0', width: '2', endian: 'big',
  multiplier: '1', adjustment: '0', startHex: '', endHex: '', maxBytes: '1048576',
}
function integer(value: string, minimum: number, maximum: number, label: string) {
  if (!/^-?\d+$/.test(value.trim())) throw new Error(`${label}: требуется целое число`)
  const n = Number(value)
  if (!Number.isSafeInteger(n) || n < minimum || n > maximum) throw new Error(`${label}: от ${minimum} до ${maximum}`)
  return n
}
export function framingSpec(draft: FramingDraft, extent: number): FramingSpec {
  const max_message_bytes = integer(draft.maxBytes, 1, 16777216, 'Лимит сообщения')
  const base = { schema_version: 'framing-1' as const, start: draft.kind === 'manual' ? 0 : integer(draft.start, 0, extent, 'Начальное смещение'), max_message_bytes, max_pieces: 200000 }
  if (draft.kind === 'manual') {
    const lines = draft.ranges.split(/\r?\n/).filter(line => line.trim())
    if (lines.length > 10000) throw new Error('Не более 10000 ручных диапазонов')
    let previous = 0
    const ranges = lines.map(line => {
      const match = /^\s*(\d+)\s*:\s*(\d+)\s*$/.exec(line)
      if (!match) throw new Error('Ручной диапазон: начало:конец, каждый на новой строке')
      const start = integer(match[1], 0, extent, 'Начало'), end = integer(match[2], 0, extent, 'Конец')
      if (start >= end || start < previous || end-start > max_message_bytes) throw new Error('Ручные диапазоны должны быть непустыми, упорядоченными, без перекрытий и внутри лимита')
      previous = end
      return { start, end }
    })
    return { ...base, rule: { kind: 'manual', ranges } }
  }
  if (draft.kind === 'fixed') return { ...base, rule: { kind: 'fixed', size: integer(draft.size, 1, max_message_bytes, 'Размер сообщения') } }
  if (draft.kind === 'length') {
    const width = integer(draft.width, 1, 8, 'Ширина поля')
    if (![1,2,4,8].includes(width)) throw new Error('Ширина поля: 1, 2, 4 или 8')
    return { ...base, rule: { kind: 'length', offset: integer(draft.offset, 0, 65536, 'Смещение поля'), width: width as 1|2|4|8, endian: draft.endian, multiplier: integer(draft.multiplier, 1, 65536, 'Множитель'), adjustment: integer(draft.adjustment, -16777216, 16777216, 'Поправка') } }
  }
  const marker = (value: string) => {
    const normalized = value.replace(/\s/g, '')
    if (!/^(?:[a-fA-F0-9]{2}){1,64}$/.test(normalized)) throw new Error('Маркер: от 1 до 64 полных HEX-байтов')
    return normalized.toLowerCase()
  }
  return { ...base, rule: { kind: 'markers', start_hex: marker(draft.startHex), end_hex: marker(draft.endHex) } }
}
export function framingSignature(spec: FramingSpec) {
  return JSON.stringify(spec, (_, value) => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])) : value)
}
