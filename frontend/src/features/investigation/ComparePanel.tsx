import { useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useSelection } from '@/shared/store'
import { byteKey, cells, diff, loadBytes, token, type Range } from './data'
import { ErrorMessage } from './Common'

export function ComparePanel({ current }: { current: Range | null }) {
  const reference = useSelection(s => s.reference)
  const enabled = !!current && !!reference && current.end-current.start <= 4096 && reference.end-reference.start <= 4096
  const left = useQuery({ queryKey: reference ? byteKey(reference.streamId, reference.start, reference.end-reference.start) : ['compare-left-empty'], queryFn: ({ signal }) => loadBytes(reference!.streamId, reference!.start, reference!.end-reference!.start, signal), enabled })
  const right = useQuery({ queryKey: current ? byteKey(current.streamId, current.start, current.end-current.start) : ['compare-right-empty'], queryFn: ({ signal }) => loadBytes(current!.streamId, current!.start, current!.end-current!.start, signal), enabled })
  const queries = [left, right]
  const maps = queries.map(q => cells(q.data))
  const count = enabled ? Math.max(reference!.end-reference!.start, current!.end-current!.start) : 0
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: Math.ceil(count/16), getScrollElement: () => scroll.current, estimateSize: () => 34, overscan: 4 })
  if (!reference) return null
  return <section className="panel stack" aria-label="Сравнение диапазонов"><h3>Сравнение байтов</h3><p className="muted text-xs">A: {reference.streamId.slice(0, 8)} [{reference.start}, {reference.end}) · B: {current ? `${current.streamId.slice(0,8)} [${current.start}, ${current.end})` : 'выберите диапазон'}. До 4096 позиций в каждом диапазоне.</p><ErrorMessage error={queries.find(q => q.error)?.error} />{!enabled && <p className="notice">Выделите диапазон до 4096 позиций. Сравнение возможно между разными потоками.</p>}<p className="muted text-xs">Красный — разные известные bytes; серый — отсутствующие, конфликтующие или ещё не загруженные данные.</p><div className="diff-scroll" ref={scroll}><div style={{ height: rows.getTotalSize(), position: 'relative', minWidth: 680 }}>{rows.getVirtualItems().map(row => <div className="diff-row" key={row.index} style={{ height: row.size, transform: `translateY(${row.start}px)` }}><span className="muted">+{(row.index*16).toString(16).padStart(4,'0')}</span>{Array.from({ length: Math.min(16, count-row.index*16) }, (_, i) => { const n = row.index*16+i; const a = maps[0].get(reference.start+n), b = maps[1].get(current!.start+n); const status = diff(a,b); return <span key={n} data-diff={status} className={`diff-cell ${status}`} title={`+${n}: ${status}`}><span>{token(a)}</span><span>{token(b)}</span></span> })}</div>)}</div></div></section>
}
