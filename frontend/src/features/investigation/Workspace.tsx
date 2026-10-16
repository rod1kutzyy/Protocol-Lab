import { useState, useRef, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { request } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { formatTime, json, useJob, usePages, utcInput, type Capture, type Project, type Session } from './data'
import { ErrorMessage, JobStatus, More } from './Common'
import { StreamPanel } from './StreamPanel'
import { ActionImport } from './ActionImport'
import { FramingPanel } from './FramingPanel'
import { WorkspaceState } from '@/shared/WorkspaceState'
import { WorkspaceScreen } from '@/shared/WorkspaceScreen'
import { navigateSection, useSection } from '@/shared/navigation'
import { Database, ScanSearch, Braces, ListChecks, FileOutput, ArrowRight } from 'lucide-react'
import { ActionsPanel } from './ActionsPanel'
import { PortablePanel } from './PortablePanel'
import { CorpusPanel } from './CorpusPanel'
import { HypothesesPanel } from './HypothesesPanel'
import { InferencePanel } from './InferencePanel'
import type { components } from '@/shared/api-types'
import type { ValidationItem } from './ValidationDetails'
import type { Job } from '@/shared/api'

export function Workspace({ project }: { project: Project }) {
  const state = useSelection()
  const section = useSection()
  const [revealRequest, setRevealRequest] = useState(0)
  const [inferenceOpened, setInferenceOpened] = useState(false)
  const [tool, setTool] = useState<'bytes' | 'actions' | 'hypotheses' | 'inference'>('bytes')
  const title = useRef<HTMLHeadingElement>(null)
  useEffect(() => { title.current?.focus({ preventScroll: true }) }, [section])
  function revealBytes() { setTool('bytes'); setRevealRequest(value => value + 1); navigateSection('research') }
  function revealRange(a: components['schemas']['StreamRange']) {
    state.selectRange({ streamId: a.stream_id, version: a.reconstruction_version, start: a.byte_range.start, end: a.byte_range.end }); revealBytes()
  }
  const navigation = useMutation({ mutationFn: async (a: components['schemas']['StreamRange']) => { const stream = await request<components['schemas']['RebuiltStream']>(`/streams/${a.stream_id}`); return request<Session>(`/sessions/${stream.session_id}`) }, onSuccess: (session, a) => { if (useSelection.getState().projectId !== project.id) return; state.selectCapture(session.capture_id); state.selectSession(session.id, a.stream_id); state.selectRange({ streamId: a.stream_id, version: a.reconstruction_version, start: a.byte_range.start, end: a.byte_range.end }); revealBytes() } })
  function navigateResult(item: ValidationItem, anchor?: components['schemas']['StreamRange']) { state.selectCapture(item.capture_id); if (item.session_id) state.selectSession(item.session_id, item.stream_id ?? null); if (anchor) state.selectRange({ streamId: anchor.stream_id, version: anchor.reconstruction_version, start: anchor.byte_range.start, end: anchor.byte_range.end }); if (item.stream_id || anchor) revealBytes(); else navigateSection('data') }
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
  const navigationItems = [
    { id: 'data', label: 'Данные', icon: Database, hint: 'Записи и журналы' },
    { id: 'research', label: 'Исследование', icon: ScanSearch, hint: 'Байты и доказательства' },
    { id: 'model', label: 'Модель', icon: Braces, hint: 'Границы и поля' },
    { id: 'validation', label: 'Проверка', icon: ListChecks, hint: 'Корпус и контрпримеры' },
    { id: 'results', label: 'Результаты', icon: FileOutput, hint: 'Отчёт и перенос' },
  ] as const
  const currentSection = navigationItems.find(item => item.id === section)!
  return <WorkspaceState><div className="workspace-shell">
    <nav className="section-navigation" aria-label="Разделы проекта">
      <p className="eyebrow">Рабочая область</p>
      {navigationItems.map(({ id, label, icon: Icon, hint }) => <a key={id} href={`#${id}`} aria-current={section === id ? 'page' : undefined}><Icon size={18} aria-hidden="true" /><span>{label}<small>{hint}</small></span></a>)}
    </nav>
    <main className="workspace-content" id="project-content" tabIndex={-1}>
      <header className="workspace-heading"><div><p className="eyebrow">{project.name}</p><h2 ref={title} tabIndex={-1}>{currentSection.label}</h2></div><small className="muted">{currentSection.hint}</small></header>
      <ErrorMessage error={navigation.error} />
      {section !== 'data' && <div className="context-bar"><div><strong>{selected.data ? `${selected.data.endpoint_a.address}:${selected.data.endpoint_a.port} ↔ ${selected.data.endpoint_b.address}:${selected.data.endpoint_b.port}` : 'Соединение не выбрано'}</strong><small className="muted">{state.captureId ? `Запись ${state.captureId.slice(0, 8)}` : 'Выберите исходные данные'}{state.range ? ` · выделение [${state.range.start}, ${state.range.end})` : ''}</small></div><div className="form-row">{selected.data?.streams.map(s => <Button size="sm" key={s.id} variant={state.streamId === s.id ? 'default' : 'outline'} aria-pressed={state.streamId === s.id} onClick={() => state.selectStream(s.id)}>{s.direction === 'a_to_b' ? 'A → B' : 'B → A'} · {s.extent} байт</Button>)}<Button size="sm" variant="outline" onClick={() => navigateSection('data')}>Сменить соединение</Button></div></div>}
      <WorkspaceScreen active={section === 'data'} label="Данные проекта">
        <div className="data-grid">
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
        <div style={{ height: rows.getTotalSize(), position: 'relative' }}>{rows.getVirtualItems().map(row => { const s = items[row.index]; return <button key={s.id} role="listitem" aria-label={`Соединение ${s.endpoint_a.address}:${s.endpoint_a.port} → ${s.endpoint_b.address}:${s.endpoint_b.port}`} aria-pressed={state.sessionId === s.id} className="session-row" style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => { state.selectSession(s.id, s.streams[0]?.id ?? null); revealBytes() }}><span><strong>{s.endpoint_a.address}:{s.endpoint_a.port} ↔ {s.endpoint_b.address}:{s.endpoint_b.port}</strong><small>Запись {s.capture_id.slice(0, 8)} · интерфейс {s.section_index}/{s.interface_id}</small></span><span><small>{formatTime(s.start_timestamp_ns)}</small>{s.packet_count} пакетов</span><span className="text-xs">{!s.start_known && 'Начало неизвестно. '}{!s.roles_known && 'Роли неизвестны. '}{s.diagnostics.join('; ') || 'Без замечаний'}</span></button> })}</div>
      </div><More query={sessions} />
    </section>
        </div>
        <ActionImport projectId={project.id} />
      </WorkspaceScreen>
      <WorkspaceScreen active={section === 'research'} label="Рабочая область исследования">
        <nav className="tool-navigation" aria-label="Инструменты исследования"><Button variant={tool === 'bytes' ? 'default' : 'outline'} aria-pressed={tool === 'bytes'} onClick={() => setTool('bytes')}>Байты и источники</Button><Button variant={tool === 'actions' ? 'default' : 'outline'} aria-pressed={tool === 'actions'} onClick={() => setTool('actions')}>Журнал действий</Button><Button variant={tool === 'hypotheses' ? 'default' : 'outline'} aria-pressed={tool === 'hypotheses'} onClick={() => setTool('hypotheses')}>Гипотезы</Button><Button variant={tool === 'inference' ? 'default' : 'outline'} aria-pressed={tool === 'inference'} onClick={() => { setInferenceOpened(true); setTool('inference') }}>Анализатор</Button><Button variant="outline" onClick={() => navigateSection('model')}>Открыть модель <ArrowRight size={15} aria-hidden="true" /></Button></nav>
        <WorkspaceScreen active={tool === 'bytes'} className="tool-screen" label="Байты и источники">
          <ErrorMessage error={selected.error} />
          {selected.data && selected.data.diagnostics.length > 0 && <p className="notice warning">{selected.data.diagnostics.join('; ')}</p>}
          {stream ? <StreamPanel key={stream.id} stream={stream} projectId={project.id} revealRequest={revealRequest} /> : <div className="panel empty-state"><ScanSearch size={30} aria-hidden="true" /><h3>Выберите соединение для исследования</h3><p>Импортируйте запись, восстановите TCP и откройте нужное соединение.</p><Button onClick={() => navigateSection('data')}>Перейти к данным</Button></div>}
        </WorkspaceScreen>
        <WorkspaceScreen active={tool === 'actions'} className="tool-screen" label="Журнал действий"><ActionsPanel projectId={project.id} onNavigate={revealBytes} /></WorkspaceScreen>
        <WorkspaceScreen active={tool === 'inference'} className="tool-screen" label="Автоматический анализ">{inferenceOpened && <InferencePanel projectId={project.id} navigate={anchor => navigation.mutate(anchor)} />}</WorkspaceScreen>
        <WorkspaceScreen active={tool === 'hypotheses'} className="tool-screen" label="Гипотезы"><HypothesesPanel projectId={project.id} navigate={anchor => navigation.mutate(anchor)} /></WorkspaceScreen>
      </WorkspaceScreen>
      <WorkspaceScreen active={section === 'model'} label="Редактор модели">
        {stream ? <FramingPanel key={stream.id} stream={stream} onNavigate={revealRange} /> : <div className="panel empty-state"><Braces size={30} aria-hidden="true" /><h3>Выберите поток для модели</h3><p>Границы сообщений и поля настраиваются независимо и проверяются на исходных байтах.</p><Button onClick={() => navigateSection('data')}>Выбрать соединение</Button></div>}
      </WorkspaceScreen>
      <WorkspaceScreen active={section === 'validation'} label="Проверка корпуса"><CorpusPanel projectId={project.id} navigate={navigateResult} /></WorkspaceScreen>
      <WorkspaceScreen active={section === 'results'} label="Результаты проекта"><PortablePanel projectId={project.id} /></WorkspaceScreen>
    </main>
  </div></WorkspaceState>
}
