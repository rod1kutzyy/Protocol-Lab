import type { components } from '@/shared/api-types'
export type CorpusDraft = { name: string; captureIds: string[]; direction: 'both' | 'a_to_b' | 'b_to_a'; address: string; port: string; startNs: string; endNs: string }
export const emptyCorpus: CorpusDraft = { name: 'Проверка протокола', captureIds: [], direction: 'both', address: '', port: '', startNs: '', endNs: '' }
export function corpusSpec(draft: CorpusDraft): components['schemas']['CorpusSpec'] {
  if (!draft.captureIds.length) throw new Error('Выберите хотя бы одну запись')
  const port = draft.port.trim() ? Number(draft.port) : null
  if (port !== null && (!Number.isInteger(port) || port < 0 || port > 65535)) throw new Error('Порт: целое число 0–65535')
  const address = draft.address.trim() || null
  if (address) { const parts = address.split('.'); if (parts.length !== 4 || parts.some(p => !/^\d+$/.test(p) || Number(p) > 255 || String(Number(p)) !== p)) throw new Error('Некорректный IPv4 адрес') }
  const start = draft.startNs.trim() || null, end = draft.endNs.trim() || null
  if ([start, end].some(v => v !== null && !/^-?\d{1,30}$/.test(v))) throw new Error('Время: целые Unix nanoseconds, до 30 цифр')
  if (start !== null && end !== null && BigInt(start) > BigInt(end)) throw new Error('Начало интервала позже конца')
  return { capture_ids: [...new Set(draft.captureIds)].sort(), direction: draft.direction, address, port, start_ns: start, end_ns: end }
}
export function draftFromCorpus(corpus: components['schemas']['StoredCorpus']): CorpusDraft {
  return { name: corpus.name, captureIds: [...corpus.spec.capture_ids], direction: corpus.spec.direction ?? 'both', address: corpus.spec.address ?? '', port: corpus.spec.port === null || corpus.spec.port === undefined ? '' : String(corpus.spec.port), startNs: corpus.spec.start_ns ?? '', endNs: corpus.spec.end_ns ?? '' }
}
