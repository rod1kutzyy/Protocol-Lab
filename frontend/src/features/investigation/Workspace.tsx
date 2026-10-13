import { useState, useRef, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { request } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { formatTime, json, useJob, usePages, utcInput, type Capture, type Project, type Session } from './data'
import { ErrorMessage, JobStatus, More } from './Common'
import { StreamPanel } from './StreamPanel'
import { ActionsPanel } from './ActionsPanel'
import { PortablePanel } from './PortablePanel'
import { CorpusPanel } from './CorpusPanel'
import { HypothesesPanel } from './HypothesesPanel'
import type { components } from '@/shared/api-types'
import type { ValidationItem } from './ValidationDetails'
import type { Job } from '@/shared/api'

export function Workspace({ project }: { project: Project }) {
  const state = useSelection()
  const [section, setSection] = useState('sources')
  const navigation = useMutation({ mutationFn: async (a: components['schemas']['StreamRange']) => { const stream = await request<components['schemas']['RebuiltStream']>(`/streams/${a.stream_id}`); return request<Session>(`/sessions/${stream.session_id}`) }, onSuccess: (session, a) => { if (useSelection.getState().projectId !== project.id) return; state.selectCapture(session.capture_id); state.selectSession(session.id, a.stream_id); state.selectRange({ streamId: a.stream_id, version: a.reconstruction_version, start: a.byte_range.start, end: a.byte_range.end }); setSection('sources') } })
  function navigateResult(item: ValidationItem, anchor?: components['schemas']['StreamRange']) { state.selectCapture(item.capture_id); if (item.session_id) state.selectSession(item.session_id, item.stream_id ?? null); if (anchor) state.selectRange({ streamId: anchor.stream_id, version: anchor.reconstruction_version, start: anchor.byte_range.start, end: anchor.byte_range.end }); setSection('sources') }
  const [file, setFile] = useState<File | null>(null)
  const [policy, setPolicy] = useState('warn')
  const [jobId, setJobId] = useState<string | null>(null)
  const [filter, setFilter] = useState({ address: '', port: '', start: '', end: '' })
  const [applied, setApplied] = useState('')
  const [filterError, setFilterError] = useState<Error | null>(null)
  const captures = usePages<Capture>(['captures', project.id], `/projects/${project.id}/captures`)
  const allCaptures = captures.data?.pages.flatMap(p => p.items) ?? []
  const job = useJob(jobId, completed => { if (completed.status === 'succeeded' && completed.kind === 'capture_import' && typeof completed.result?.capture_id === 'string') state.selectCapture(completed.result.capture_id) })
  const busy = !!jobId && (!job.data || !['succeeded', 'failed', 'cancelled'].includes(job.data.status))
  const upload = useMutation({ mutationFn: () => { const body = new FormData(); if (file) body.append('file', file); body.append('checksum_policy', policy); return request<Job>(`/projects/${project.id}/captures`, { method: 'POST', body }) }, onSuccess: result => { setJobId(result.id); state.selectJob(result.id) } })
  const reconstruct = useMutation({ mutationFn: () => request<Job>(`/captures/${state.captureId}/reconstruct`, json({})), onSuccess: result => { setJobId(result.id); state.selectJob(result.id) } })
  const query = new URLSearchParams(applied)
  if (state.captureId) query.set('capture_id', state.captureId)
  const sessions = usePages<Session>(['sessions', project.id, state.captureId, applied], `/projects/${project.id}/sessions?${query}`)
  const items = sessions.data?.pages.flatMap(p => p.items) ?? []
  const selected = useQuery({ queryKey: ['session', state.sessionId], queryFn: () => request<Session>(`/sessions/${state.sessionId}`), enabled: !!state.sessionId })
  const stream = selected.data?.streams.find(s => s.id === state.streamId)
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: items.length, getScrollElement: () => scroll.current, estimateSize: () => 76, overscan: 5 })
  const captureDetails = useQuery({ queryKey: ['capture', state.captureId], queryFn: () => request<Capture>(`/captures/${state.captureId}`), enabled: !!state.captureId })
  const currentCapture = allCaptures.find(c => c.id === state.captureId) ?? captureDetails.data
  const visibleCaptures = currentCapture && !allCaptures.some(c => c.id === currentCapture.id) ? [...allCaptures, currentCapture] : allCaptures
  useEffect(() => { if (section === 'sources' && stream && state.range?.streamId === stream.id) requestAnimationFrame(() => document.getElementById(`stream-hex-${stream.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })) }, [section, stream?.id, state.range?.start, state.range?.end])
  function applyFilters() {
    try {
      const q = new URLSearchParams()
      if (filter.address.trim()) q.set('address', filter.address.trim())
      if (filter.port) { const n = Number(filter.port); if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error('Порт: целое число от 0 до 65535'); q.set('port', filter.port) }
      if (filter.start) q.set('start_ns', utcInput(filter.start))
      if (filter.end) q.set('end_ns', utcInput(filter.end))
      if (filter.start && filter.end && filter.start > filter.end) throw new Error('Начало интервала позже конца')
      setApplied(q.toString()); setFilterError(null)
    } catch (error) { setFilterError(error as Error) }
  }
  return <div className="stack workspace">
    <div className="workspace-title"><div><p className="eyebrow">Исследование протокола</p><h2>{project.name}</h2></div><small className="muted">Локальный проект · {project.id.slice(0, 8)}</small></div>
    <nav className="form-row" aria-label="Работа с проектом"><Button variant={section === 'sources' ? 'default' : 'outline'} onClick={() => setSection('sources')}>Исходные данные</Button><Button variant={section === 'portable' ? 'default' : 'outline'} onClick={() => setSection('portable')}>Перенос и отчёт</Button><Button variant={section === 'validation' ? 'default' : 'outline'} onClick={() => setSection('validation')}>Гипотезы и проверка корпуса</Button></nav>
    <div hidden={section !== 'portable'} className="research-tab"><PortablePanel projectId={project.id} /></div>
    <ErrorMessage error={navigation.error} />
    <div hidden={section !== 'validation'} className="research-tab"><div className="stack"><HypothesesPanel projectId={project.id} navigate={anchor => navigation.mutate(anchor)} /><CorpusPanel projectId={project.id} navigate={navigateResult} /></div></div>
    <div hidden={section !== 'sources'} className="research-tab"><div className="stack">
    <section className="panel stack" aria-label="Импорт записи">
      <h3>Записи PCAP / PCAPNG</h3>
      <form className="form-row" onSubmit={e => { e.preventDefault(); upload.mutate() }}>
        <label>Файл записи<input type="file" accept=".pcap,.pcapng" onChange={e => setFile(e.target.files?.[0] ?? null)} required /></label>
        <label>Checksum policy<select value={policy} onChange={e => setPolicy(e.target.value)}><option value="warn">Предупреждать</option><option value="ignore">Не проверять</option><option value="reject">Исключать неверные</option></select></label>
        <Button disabled={!file || busy || upload.isPending}>Импортировать запись</Button>
      </form>
      <JobStatus job={job.data} /><ErrorMessage error={upload.error ?? reconstruct.error ?? captures.error ?? captureDetails.error ?? job.error} />
      <div className="form-row"><label>Запись для исследования<select value={state.captureId ?? ''} onChange={e => state.selectCapture(e.target.value || null)}><option value="">Все записи</option>{visibleCaptures.map((c, i) => <option value={c.id} key={c.id}>Запись {i + 1} · {c.sha256.slice(0, 12)} · {c.packet_count} пакетов</option>)}</select></label><Button variant="outline" disabled={!state.captureId || busy || reconstruct.isPending} onClick={() => reconstruct.mutate()}>Восстановить TCP</Button><More query={captures} /></div>
      {currentCapture && <div className="notice"><p>{currentCapture.format.toUpperCase()} · {currentCapture.packet_count} пакетов · {currentCapture.size_bytes} байт · policy: {currentCapture.checksum_policy}</p><p className="break-all text-xs">SHA-256: {currentCapture.sha256}</p>{Object.keys(currentCapture.diagnostics).length ? <ul>{Object.entries(currentCapture.diagnostics).map(([code, count]) => <li key={code}>{code}: {count}</li>)}</ul> : <p>Диагностика импорта: замечаний нет.</p>}</div>}
    </section>
    <section className="panel stack" aria-labelledby="sessions-title">
      <h3 id="sessions-title">TCP-соединения</h3>
      <form className="form-row filters" onSubmit={e => { e.preventDefault(); applyFilters() }}>
        <label>IPv4 адрес<input value={filter.address} onChange={e => setFilter({ ...filter, address: e.target.value })} placeholder="192.0.2.1" /></label>
        <label>Порт<input type="number" min={0} max={65535} value={filter.port} onChange={e => setFilter({ ...filter, port: e.target.value })} /></label>
        <label>Время UTC от<input type="datetime-local" value={filter.start} onChange={e => setFilter({ ...filter, start: e.target.value })} /></label>
        <label>Время UTC до<input type="datetime-local" value={filter.end} onChange={e => setFilter({ ...filter, end: e.target.value })} /></label>
        <Button size="sm" variant="outline">Применить фильтры</Button><Button type="button" size="sm" variant="outline" onClick={() => { setFilter({ address: '', port: '', start: '', end: '' }); setApplied(''); setFilterError(null) }}>Сбросить</Button>
      </form>
      <p className="muted text-xs">Интервал пересекает время соединения. Сессии без временных меток не попадают в фильтр по времени.</p>
      <ErrorMessage error={sessions.error ?? filterError} />
      <div className="session-head"><span>Стороны соединения</span><span>Время UTC / пакеты</span><span>Диагностика</span></div>
      <div ref={scroll} className="session-list" role="list" aria-label="TCP-сессии">
        {sessions.isLoading && <p className="muted p-3">Загрузка соединений…</p>}
        {!sessions.isLoading && !items.length && <p className="muted p-3">Соединений нет. Восстановите TCP для выбранной записи или измените фильтры.</p>}
        <div style={{ height: rows.getTotalSize(), position: 'relative' }}>{rows.getVirtualItems().map(row => { const s = items[row.index]; return <button key={s.id} role="listitem" aria-label={`Соединение ${s.endpoint_a.address}:${s.endpoint_a.port} → ${s.endpoint_b.address}:${s.endpoint_b.port}`} aria-pressed={state.sessionId === s.id} className="session-row" style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => state.selectSession(s.id, s.streams[0]?.id ?? null)}><span><strong>{s.endpoint_a.address}:{s.endpoint_a.port} ↔ {s.endpoint_b.address}:{s.endpoint_b.port}</strong><small>Запись {s.capture_id.slice(0, 8)} · интерфейс {s.section_index}/{s.interface_id}</small></span><span><small>{formatTime(s.start_timestamp_ns)}</small>{s.packet_count} пакетов</span><span className="text-xs">{!s.start_known && 'Начало неизвестно. '}{!s.roles_known && 'Роли неизвестны. '}{s.diagnostics.join('; ') || 'Без замечаний'}</span></button> })}</div>
      </div><More query={sessions} />
    </section>
    <ErrorMessage error={selected.error} />
    {selected.data && <section className="stack" aria-label="Потоки соединения"><div className="form-row"><h3>Направление потока</h3>{selected.data.streams.map(s => <Button key={s.id} variant={state.streamId === s.id ? 'default' : 'outline'} onClick={() => state.selectStream(s.id)}>{s.direction === 'a_to_b' ? 'A → B' : 'B → A'} · {s.extent} байт</Button>)}</div>{selected.data.diagnostics.length > 0 && <p className="notice">{selected.data.diagnostics.join('; ')}</p>}{stream ? <StreamPanel key={stream.id} stream={stream} projectId={project.id} /> : <p className="notice">Выберите доступное направление. Ошибка направления не скрывает остальные данные.</p>}</section>}
    <ActionsPanel key={project.id} projectId={project.id} />
    </div></div>
  </div>
}
