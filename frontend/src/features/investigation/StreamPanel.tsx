import { useWorkspaceState } from '@/shared/WorkspaceState'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQueries } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { request, type Job } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { useSelection } from '@/shared/store'
import { ascii, byteKey, cells, json, loadBytes, token, useJob, type Stream } from './data'
import { ErrorMessage, JobStatus } from './Common'
import { SourcesPanel } from './SourcesPanel'
import { ComparePanel } from './ComparePanel'
import { WorkspaceScreen, useScreenVisible } from '@/shared/WorkspaceScreen'

const PAGE = 4096
const WINDOW = 65536
export function StreamPanel({ stream, projectId, revealRequest }: { stream: Stream; projectId: string; revealRequest: number }) {
  const visible = useScreenVisible()
  const handledReveal = useRef(0)
  const { range, selectRange, pin, reference } = useSelection()
  const [comparing, setComparing] = useWorkspaceState(`stream:${stream.id}:comparing`, false)
  const [windowStart, setWindowStart] = useWorkspaceState(`stream:${stream.id}:windowStart`, 0)
  const [jump, setJump] = useWorkspaceState(`stream:${stream.id}:jump`, '0')
  const [start, setStart] = useWorkspaceState(`stream:${stream.id}:start`, '0'), [end, setEnd] = useWorkspaceState(`stream:${stream.id}:end`, String(Math.min(stream.extent, 16)))
  const [error, setError] = useState<Error | null>(null)
  const [pattern, setPattern] = useWorkspaceState(`stream:${stream.id}:pattern`, ''), [searchId, setSearchId] = useWorkspaceState<string | null>(`stream:${stream.id}:searchId`, null)
  const [searchResult, setSearchResult] = useWorkspaceState<{ matches: number[]; complete: boolean; next_offset: number | null; skipped_bytes: number; pattern_hex: string } | null>(`stream:${stream.id}:searchResult`, null)
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: Math.ceil(Math.min(WINDOW, stream.extent - windowStart) / 16), getScrollElement: () => scroll.current, estimateSize: () => 28, overscan: 8 })
  const virtual = rows.getVirtualItems()
  const pages = [...new Set(virtual.map(row => Math.floor((windowStart + row.index * 16) / PAGE) * PAGE))]
  const queries = useQueries({ queries: pages.map(offset => ({ queryKey: byteKey(stream.id, offset, Math.min(PAGE, stream.extent - offset)), queryFn: ({ signal }: { signal: AbortSignal }) => loadBytes(stream.id, offset, Math.min(PAGE, stream.extent - offset), signal), staleTime: 60000 })) })
  const displayed = useMemo(() => { const result = new Map<number, ReturnType<typeof cells> extends Map<number, infer C> ? C : never>(); for (const q of queries) for (const [offset, cell] of cells(q.data)) result.set(offset, cell); return result }, [queries])
  const active = range?.streamId === stream.id ? range : null
  function showWindow(offset: number) { const n = Math.max(0, Math.min(Math.floor(offset / 16) * 16, Math.max(0, stream.extent - 1))); setWindowStart(n); setJump(String(n)); scroll.current?.scrollTo({ top: 0 }) }
  useEffect(() => { if (active) { setStart(String(active.start)); setEnd(String(active.end)); if (active.start < windowStart || active.start >= windowStart + WINDOW) showWindow(active.start); else { const index = Math.floor((active.start-windowStart)/16), top = index*28; if (scroll.current && (top < scroll.current.scrollTop || top >= scroll.current.scrollTop+scroll.current.clientHeight)) rows.scrollToIndex(index, { align: 'start' }) } } }, [active?.start, active?.end])
  useEffect(() => {
    if (!visible || !active || !revealRequest || handledReveal.current === revealRequest) return
    const frame = requestAnimationFrame(() => {
      handledReveal.current = revealRequest
      showWindow(active.start)
      scroll.current?.closest('[aria-label="Рабочая область исследования"]')?.scrollTo({ top: 0 })
    })
    return () => cancelAnimationFrame(frame)
  }, [visible, revealRequest, active?.start, active?.end])
  function select(left: number, right: number, reveal = false) {
    if (!Number.isInteger(left) || !Number.isInteger(right) || left < 0 || right > stream.extent || right <= left) { setError(new Error('Диапазон: 0 ≤ начало < конец ≤ размер потока')); return }
    selectRange({ streamId: stream.id, version: stream.reconstruction_version, start: left, end: right }); setError(null); if (reveal) showWindow(left)
  }
  const searchJob = useJob(searchId, job => { if (job.status === 'succeeded') setSearchResult(job.result as typeof searchResult) })
  const searching = !!searchId && (!searchJob.data || !['succeeded', 'failed', 'cancelled'].includes(searchJob.data.status))
  const search = useMutation({ mutationFn: ({ offset, pattern: input }: { offset: number; pattern: string }) => { const normalized = input.replace(/\s/g, ''); if (!/^(?:[0-9a-fA-F]{2}){1,256}$/.test(normalized)) throw new Error('HEX-последовательность: от 1 до 256 полных байтов'); return request<Job>(`/streams/${stream.id}/search`, json({ pattern_hex: normalized, start: offset })) }, onSuccess: job => setSearchId(job.id) })
  return <div className="stack stream-workspace">
    <div className="research-columns">
    <section className="panel stack" id={`stream-hex-${stream.id}`} aria-labelledby="hex-title">
      <div className="workspace-title"><h3 id="hex-title">HEX / ASCII</h3><small>{stream.extent} позиций · {stream.reconstruction_version}</small></div>
      <p className="muted text-xs">Клик — начало выделения, Shift+клик — конец. Диапазоны [начало, конец). ?? — конфликт, — — пропуск/усечение, … — загрузка.</p>
      <div className="form-row"><label>Перейти к смещению<input type="number" min={0} max={Math.max(0, stream.extent-1)} value={jump} onChange={e => setJump(e.target.value)} /></label><Button size="sm" variant="outline" disabled={!stream.extent} onClick={() => { const n = Number(jump); if (!Number.isInteger(n) || n < 0 || n >= stream.extent) setError(new Error('Смещение находится вне потока')); else { showWindow(n); setError(null) } }}>Перейти</Button><Button size="sm" variant="outline" disabled={!windowStart} onClick={() => showWindow(Math.max(0, windowStart-WINDOW))}>Предыдущее окно</Button><Button size="sm" variant="outline" disabled={windowStart+WINDOW >= stream.extent} onClick={() => showWindow(windowStart+WINDOW)}>Следующее окно</Button></div>
      <p className="muted text-xs">Окно [{windowStart}, {Math.min(stream.extent, windowStart+WINDOW)}), загружаются только видимые страницы по 4096 позиций.</p>
      <ErrorMessage error={error ?? queries.find(q => q.error)?.error} />
      <div className="hex-head"><span>Смещение</span><span>00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</span><span>ASCII</span></div>
      <div ref={scroll} className="hex-scroll" aria-label="Байты потока">
        {!stream.extent && <p className="p-4 muted">В этом направлении нет доступных байтов.</p>}
        <div style={{ height: rows.getTotalSize(), position: 'relative', minWidth: 640 }}>{virtual.map(row => { const offset = windowStart + row.index*16; const offsets = Array.from({ length: Math.min(16, stream.extent-offset) }, (_, i) => offset+i); return <div className="hex-row" key={offset} style={{ transform: `translateY(${row.start}px)`, height: row.size }}><span className="hex-offset">{offset.toString(16).padStart(8, '0').toUpperCase()}</span><div className="hex-cells">{offsets.map(n => { const cell = displayed.get(n); return <button key={n} className={`byte ${cell?.status ?? 'loading'} ${active && n >= active.start && n < active.end ? 'selected' : ''}`} title={`${n}: ${cell?.status ?? 'загрузка'} ${cell?.values.join(' / ') ?? ''}`} aria-label={`Байт ${n}: ${token(cell)}`} onClick={e => select(e.shiftKey && active ? Math.min(active.start, n) : n, e.shiftKey && active ? Math.max(active.start, n)+1 : n+1)}>{token(cell)}</button> })}</div><span className="hex-ascii">{offsets.map(n => ascii(displayed.get(n))).join('')}</span></div> })}</div>
      </div>
      <div className="form-row"><label>Начало диапазона<input type="number" min={0} value={start} onChange={e => setStart(e.target.value)} /></label><label>Конец диапазона (не включён)<input type="number" min={1} value={end} onChange={e => setEnd(e.target.value)} /></label><Button size="sm" onClick={() => select(Number(start), Number(end), true)}>Выделить диапазон</Button><Button size="sm" variant="outline" disabled={!active || active.end-active.start>4096} onClick={pin}>Запомнить для сравнения</Button></div>
      {active && <p className="notice">Выделено [{active.start}, {active.end}) · {active.end-active.start} позиций. Для сравнения можно запомнить до 4096 позиций.</p>}
      <form className="form-row" onSubmit={e => { e.preventDefault(); setSearchResult(null); search.mutate({ offset: 0, pattern }) }}><label>Поиск HEX-последовательности<input value={pattern} onChange={e => setPattern(e.target.value)} placeholder="48 45 4C 4C 4F" /></label><Button size="sm" variant="outline" disabled={!stream.extent || searching || search.isPending}>Найти в потоке</Button></form>
      <p className="muted text-xs">Поиск только по достоверным байтам. Конфликты и пропуски разрывают последовательность.</p>
      <ErrorMessage error={search.error ?? searchJob.error} /><JobStatus job={searchJob.data} />
      {searchResult && <div className="notice"><p>Совпадений на странице: {searchResult.matches.length}. Пропущено неопределенных позиций: {searchResult.skipped_bytes}. {searchResult.complete ? 'Поиск завершён.' : 'Есть следующая страница результатов.'}</p><div className="matches">{searchResult.matches.map(offset => <Button size="sm" variant="outline" key={offset} onClick={() => select(offset, offset+searchResult.pattern_hex.length/2, true)}>Смещение {offset}</Button>)}</div>{searchResult.next_offset != null && <Button size="sm" disabled={searching} onClick={() => { setPattern(searchResult.pattern_hex); search.mutate({ offset: searchResult.next_offset!, pattern: searchResult.pattern_hex }) }}>Следующие совпадения</Button>}</div>}
    </section>
    <aside className="range-inspector" aria-label="Инспектор диапазона">
      {active ? <SourcesPanel key={`${active.streamId}:${active.start}:${active.end}`} range={active} projectId={projectId} /> : <div className="panel stack"><h3>Инспектор диапазона</h3><p className="muted">Выделите байты, чтобы увидеть исходные пакеты и добавить наблюдение. Пропуски и конфликты остаются видимыми.</p></div>}
    </aside>
    </div>
    <div className="form-row"><Button size="sm" variant="outline" aria-expanded={comparing} onClick={() => setComparing(!comparing)}>{comparing ? 'Скрыть сравнение' : 'Сравнить диапазоны'}</Button>{reference && <span className="muted text-xs">Опорный: {reference.streamId.slice(0, 8)} [{reference.start}, {reference.end})</span>}</div>
    <WorkspaceScreen active={comparing} className="tool-screen" label="Сравнение диапазонов">
      {reference ? <ComparePanel current={active} /> : <p className="notice">Выделите диапазон и нажмите «Запомнить для сравнения», затем выберите второй диапазон в этом или другом потоке.</p>}
    </WorkspaceScreen>
  </div>
}
