import type { components } from '@/shared/api-types'
import type { Job } from '@/shared/api'
import { request, terminal } from '@/shared/api'
import { useEffect, useRef } from 'react'
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query'

export type Project = components['schemas']['Project']
export type Capture = components['schemas']['StoredCapture']
export type Session = components['schemas']['SessionView']
export type Stream = components['schemas']['RebuiltStream']
export type Bytes = components['schemas']['StreamBytes']
export type Evidence = components['schemas']['Evidence']
export type Packet = components['schemas']['IndexedPacket']
export type Action = components['schemas']['ActionEvent']
export type Log = components['schemas']['StoredLog']
export type Link = components['schemas']['ActionLink']
export interface Page<T> { items: T[]; next_offset: number | null }
export interface Range { streamId: string; version: string; start: number; end: number }
export const json = (body: unknown, method = 'POST'): RequestInit => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
export const anchor = (range: Range) => ({ stream_id: range.streamId, reconstruction_version: range.version, byte_range: { start: range.start, end: range.end } })
export const byteKey = (streamId: string, offset: number, length: number) => ['bytes', streamId, offset, length]
export const loadBytes = (streamId: string, offset: number, length: number, signal?: AbortSignal) => request<Bytes>(`/streams/${streamId}/bytes?offset=${offset}&length=${length}`, { signal })

export function usePages<T>(key: unknown[], path: string, enabled = true) {
  return useInfiniteQuery({ queryKey: key, initialPageParam: 0,
    queryFn: ({ pageParam, signal }) => request<Page<T>>(`${path}${path.includes('?') ? '&' : '?'}offset=${pageParam}&limit=100`, { signal }),
    getNextPageParam: (page) => page.next_offset ?? undefined, enabled })
}
export function useJob(id: string | null, done: (job: Job) => void) {
  const callback = useRef(done); callback.current = done
  const seen = useRef<string | null>(null)
  const client = useQueryClient()
  const query = useQuery({ queryKey: ['job', id], queryFn: () => request<Job>(`/jobs/${id}`), enabled: !!id,
    refetchInterval: (q) => q.state.data && terminal(q.state.data.status) ? false : 400 })
  useEffect(() => {
    if (query.data && terminal(query.data.status) && query.data.id !== seen.current) {
      seen.current = query.data.id; callback.current(query.data)
      for (const key of ['captures', 'sessions', 'logs', 'actions', 'links', 'jobs', 'framing-runs', 'interpretation-runs', 'validation-runs', 'validation-currentness']) void client.invalidateQueries({ queryKey: [key] })
    }
  }, [query.data, client])
  return query
}
export function formatTime(ns: string | null | undefined) {
  if (ns == null) return 'Время неизвестно'
  try { return new Date(Number(BigInt(ns) / 1000000n)).toISOString().replace('T', ' ').replace('Z', ' UTC') } catch { return ns + ' ns' }
}
export function utcInput(value: string) {
  const ms = Date.parse(value + 'Z')
  if (!Number.isFinite(ms)) throw new Error('Некорректное время UTC')
  return (BigInt(ms) * 1000000n).toString()
}
export type Cell = { status: string; values: string[] }
export function cells(data: Bytes | undefined): Map<number, Cell> {
  const result = new Map<number, Cell>()
  for (const block of data?.blocks ?? []) {
    for (let offset = block.byte_range.start; offset < block.byte_range.end; offset++) {
      const index = (offset - block.byte_range.start) * 2
      result.set(offset, { status: block.status, values: [...new Set(block.variants.map(v => v.data_hex.slice(index, index + 2)))] })
    }
  }
  return result
}
export function diff(left?: Cell, right?: Cell): 'equal' | 'different' | 'unknown' {
  if (!left || !right || left.status !== 'known' || right.status !== 'known') return 'unknown'
  return left.values[0] === right.values[0] ? 'equal' : 'different'
}
export const ascii = (cell?: Cell) => cell?.status === 'known' && cell.values.length === 1 ? (() => { const n = parseInt(cell.values[0], 16); return n >= 32 && n <= 126 ? String.fromCharCode(n) : '.' })() : '?'
export const token = (cell?: Cell) => !cell ? '…' : cell.status === 'known' ? cell.values[0]?.toUpperCase() : cell.status === 'ambiguous' ? '??' : '—'
