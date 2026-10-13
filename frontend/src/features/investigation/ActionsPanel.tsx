import { useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { components } from '@/shared/api-types'
import { request, type Job } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { anchor, formatTime, json, useJob, usePages, type Action, type Link, type Log, type Session, type Stream } from './data'
import { ErrorMessage, JobStatus, More } from './Common'

function ClockForm({ log }: { log: Log }) {
  const [value, setValue] = useState(log.clock_offset_ns ?? '0')
  const client = useQueryClient()
  const save = useMutation({ mutationFn: () => request(`/action-logs/${log.id}/clock`, json({ clock_offset_ns: value, expected_revision: log.clock_revision }, 'PATCH')), onSuccess: () => { void client.invalidateQueries({ queryKey: ['logs'] }); void client.invalidateQueries({ queryKey: ['correlations'] }) } })
  return <form className="clock-form" onSubmit={e => { e.preventDefault(); save.mutate() }}><div><strong>Журнал {log.id.slice(0,8)}</strong><small>{log.event_count}/{log.row_count} действий · отклонено {log.rejected_rows} строк · {log.mapping.timestamp_format}</small></div><label>Поправка часов, ns<input value={value} onChange={e => setValue(e.target.value)} pattern="-?[0-9]{1,19}" required /></label><Button size="sm" variant="outline" disabled={save.isPending}>Сохранить поправку</Button><ErrorMessage error={save.error} />{log.rejected_rows > 0 && <p className="muted text-xs">{log.diagnostics.map(d => `строка ${String(d.row_index)}: ${String(d.code)}`).join('; ')}{!log.diagnostics_complete && '; подробности первых 100 ошибок'}</p>}</form>
}

export function ActionsPanel({ projectId }: { projectId: string }) {
  const state = useSelection()
  const [file, setFile] = useState<File | null>(null), [format, setFormat] = useState('csv'), [delimiter, setDelimiter] = useState(',')
  const [preview, setPreview] = useState<components['schemas']['LogPreview'] | null>(null)
  const [timeField, setTimeField] = useState(''), [labelField, setLabelField] = useState(''), [parameters, setParameters] = useState(''), [timeFormat, setTimeFormat] = useState('iso8601')
  const [jobId, setJobId] = useState<string | null>(null), [timeOnly, setTimeOnly] = useState(false), [windowMs, setWindowMs] = useState('0')
  const [selected, setSelected] = useState<Action | null>(null), [note, setNote] = useState(''), [linkError, setLinkError] = useState<Error | null>(null)
  const client = useQueryClient()
  const job = useJob(jobId, () => {})
  const busy = !!jobId && (!job.data || !['succeeded', 'failed', 'cancelled'].includes(job.data.status))
  const peek = useMutation({ mutationFn: () => { const body = new FormData(); if (file) body.append('file', file); body.append('format', format); body.append('delimiter', delimiter); return request<components['schemas']['LogPreview']>(`/projects/${projectId}/action-logs/preview`, { method: 'POST', body }) }, onSuccess: p => { setPreview(p); setTimeField(p.fields[0] ?? ''); setLabelField(p.fields[1] ?? p.fields[0] ?? ''); setParameters('') } })
  const upload = useMutation({ mutationFn: () => { const body = new FormData(); if (file) body.append('file', file); body.append('format', format); body.append('mapping_json', JSON.stringify({ timestamp_field: timeField, label_field: labelField, parameters_field: parameters || null, timestamp_format: timeFormat, delimiter })); return request<Job>(`/projects/${projectId}/action-logs`, { method: 'POST', body }) }, onSuccess: j => { setJobId(j.id); state.selectJob(j.id) } })
  const logs = usePages<Log>(['logs', projectId], `/projects/${projectId}/action-logs`)
  const actions = usePages<Action>(['actions', projectId], `/projects/${projectId}/actions`, !timeOnly)
  const range = state.range
  const allowed = !!range && range.end-range.start <= 65536
  const windowValue = Number(windowMs)
  const validWindow = Number.isInteger(windowValue) && windowValue >= 0 && windowValue <= 60000
  const matching = useInfiniteQuery({ queryKey: ['correlations', projectId, range, windowMs], initialPageParam: 0, queryFn: ({ pageParam, signal }) => request<components['schemas']['CorrelatedActions']>(`/streams/${range!.streamId}/actions?offset=${range!.start}&length=${range!.end-range!.start}&window_ns=${windowValue*1000000}&page=${pageParam}&limit=100`, { signal }), getNextPageParam: p => p.next_offset ?? undefined, enabled: timeOnly && allowed && validWindow })
  const items = timeOnly ? matching.data?.pages.flatMap(p => p.items) ?? [] : actions.data?.pages.flatMap(p => p.items) ?? []
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: items.length, getScrollElement: () => scroll.current, estimateSize: () => 60, overscan: 5 })
  const links = usePages<Link>(['links', projectId], `/projects/${projectId}/action-links`)
  const bind = useMutation({ mutationFn: () => request(`/projects/${projectId}/actions/${selected!.id}/links`, json({ text: note || `Ручная привязка: ${selected!.label}`, anchors: [anchor(range!)] })), onSuccess: () => { setNote(''); void client.invalidateQueries({ queryKey: ['links'] }); void client.invalidateQueries({ queryKey: ['observations'] }) } })
  const openLink = useMutation({ mutationFn: async (link: Link) => { const a = link.observation.anchors[0]; if (!a) throw new Error('В привязке нет диапазона'); const stream = await request<Stream>(`/streams/${a.stream_id}`); const session = await request<Session>(`/sessions/${stream.session_id}`); state.selectCapture(session.capture_id); state.selectSession(session.id, stream.id); state.selectRange({ streamId: stream.id, version: a.reconstruction_version, start: a.byte_range.start, end: a.byte_range.end }); setLinkError(null) }, onError: e => setLinkError(e) })
  return <section className="panel stack" aria-labelledby="actions-title"><h3 id="actions-title">Журнал действий</h3><p className="muted text-xs">CSV / JSON, UTF-8. Сначала выберите соответствие полей. Время capture = время log + поправка часов.</p>
    <form className="form-row" onSubmit={e => { e.preventDefault(); peek.mutate() }}><label>Файл журнала<input type="file" accept=".csv,.json" onChange={e => { setFile(e.target.files?.[0] ?? null); setPreview(null) }} required /></label><label>Формат<select value={format} onChange={e => { setFormat(e.target.value); setPreview(null) }}><option value="csv">CSV</option><option value="json">JSON</option></select></label><label>Разделитель CSV<select value={delimiter} onChange={e => { setDelimiter(e.target.value); setPreview(null) }}><option value=",">Запятая</option><option value=";">Точка с запятой</option><option value={'\t'}>Табуляция</option></select></label><Button size="sm" variant="outline" disabled={!file || peek.isPending}>Посмотреть поля</Button></form>
    <ErrorMessage error={peek.error ?? upload.error ?? logs.error} />
    {preview && <div className="stack"><p className="notice">{preview.row_count} строк · поля: {preview.fields.join(', ')}</p><form className="form-row" onSubmit={e => { e.preventDefault(); upload.mutate() }}><label>Поле времени<select value={timeField} onChange={e => setTimeField(e.target.value)}>{preview.fields.map(f => <option key={f}>{f}</option>)}</select></label><label>Поле действия<select value={labelField} onChange={e => setLabelField(e.target.value)}>{preview.fields.map(f => <option key={f}>{f}</option>)}</select></label><label>Поле параметров<select value={parameters} onChange={e => setParameters(e.target.value)}><option value="">Не задано</option>{preview.fields.map(f => <option key={f}>{f}</option>)}</select></label><label>Формат времени<select value={timeFormat} onChange={e => setTimeFormat(e.target.value)}><option value="iso8601">ISO 8601 с timezone</option><option value="unix_s">Unix, секунды</option><option value="unix_ms">Unix, миллисекунды</option><option value="unix_ns">Unix, наносекунды</option></select></label><Button size="sm" disabled={busy || upload.isPending}>Импортировать журнал</Button></form></div>}
    <JobStatus job={job.data} />
    {logs.data?.pages.flatMap(p => p.items).map(log => <ClockForm key={`${log.id}:${log.clock_revision}`} log={log} />)}<More query={logs} />
    <div className="form-row"><label className="checkbox"><input type="checkbox" checked={timeOnly} onChange={e => setTimeOnly(e.target.checked)} />По времени выделенных байтов</label><label>Допуск, ms<input type="number" min={0} max={60000} value={windowMs} onChange={e => setWindowMs(e.target.value)} /></label></div>
    <p className="muted text-xs">Совпадение по времени — кандидат, а не доказательство связи. Временной интервал учитывает исходные пакеты и повторные передачи.</p>
    {timeOnly && (!allowed || !validWindow) && <p className="notice">Выделите диапазон до 65536 позиций и задайте целый допуск 0–60000 ms.</p>}
    {timeOnly && matching.data && <p className="notice">Интервал источников: {formatTime(matching.data.pages[0].source_start_ns)} — {formatTime(matching.data.pages[0].source_end_ns)}. Пакетов без времени: {matching.data.pages[0].unknown_packet_timestamps}.</p>}
    <ErrorMessage error={timeOnly ? matching.error : actions.error} />
    <div className="action-list" ref={scroll} aria-label="Действия"><div style={{ height: rows.getTotalSize(), position: 'relative' }}>{rows.getVirtualItems().map(row => { const action = items[row.index]; return <button key={action.id} className="action-row" aria-label={`Действие ${action.label}, строка ${action.row_index}`} aria-pressed={selected?.id === action.id} style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => setSelected(action)}><strong>{action.label}</strong><small>{formatTime(action.timestamp_ns)} · строка {action.row_index}</small><span>{action.parameters_json}</span></button> })}</div>{!items.length && <p className="muted p-3">Действий в этой выборке нет.</p>}</div><More query={timeOnly ? matching : actions} />
    {selected && <div className="notice stack"><h4>Выбрано действие: {selected.label}</h4><p>Исходное время: {selected.timestamp_ns} ns · журнал {selected.log_id.slice(0,8)} · строка {selected.row_index}</p><pre className="wrap-json">{selected.parameters_json}</pre><label>Комментарий к ручной привязке<input value={note} onChange={e => setNote(e.target.value)} maxLength={10000} /></label><Button size="sm" disabled={!allowed || bind.isPending} onClick={() => bind.mutate()}>Привязать действие к выделению</Button></div>}
    <ErrorMessage error={bind.error ?? links.error ?? linkError} />
    {links.data?.pages.flatMap(p => p.items).map(link => <div className="observation" key={link.id}><strong>Ручная привязка</strong> · {link.observation.text}<Button size="sm" variant="outline" disabled={openLink.isPending} onClick={() => openLink.mutate(link)}>Открыть связанные байты</Button></div>)}<More query={links} />
  </section>
}
