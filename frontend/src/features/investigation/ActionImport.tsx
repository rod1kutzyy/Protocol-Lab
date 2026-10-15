import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { components } from '@/shared/api-types'
import { request, type Job } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { json, useJob, usePages, type Log } from './data'
import { ErrorMessage, JobStatus, More } from './Common'

function ClockForm({ log }: { log: Log }) {
  const [value, setValue] = useState(log.clock_offset_ns ?? '0')
  const client = useQueryClient()
  const save = useMutation({ mutationFn: () => request(`/action-logs/${log.id}/clock`, json({ clock_offset_ns: value, expected_revision: log.clock_revision }, 'PATCH')), onSuccess: () => { void client.invalidateQueries({ queryKey: ['logs'] }); void client.invalidateQueries({ queryKey: ['correlations'] }) } })
  return <form className="clock-form" onSubmit={e => { e.preventDefault(); save.mutate() }}><div><strong>Журнал {log.id.slice(0,8)}</strong><small>{log.event_count}/{log.row_count} действий · отклонено {log.rejected_rows} строк · {log.mapping.timestamp_format}</small></div><label>Поправка часов, ns<input value={value} onChange={e => setValue(e.target.value)} pattern="-?[0-9]{1,19}" required /></label><Button size="sm" variant="outline" disabled={save.isPending}>Сохранить поправку</Button><ErrorMessage error={save.error} />{log.rejected_rows > 0 && <p className="muted text-xs">{log.diagnostics.map(d => `строка ${String(d.row_index)}: ${String(d.code)}`).join('; ')}{!log.diagnostics_complete && '; подробности первых 100 ошибок'}</p>}</form>
}

export function ActionImport({ projectId }: { projectId: string }) {
  const state = useSelection()
  const [file, setFile] = useState<File | null>(null), [format, setFormat] = useState('csv'), [delimiter, setDelimiter] = useState(',')
  const [preview, setPreview] = useState<components['schemas']['LogPreview'] | null>(null)
  const [timeField, setTimeField] = useState(''), [labelField, setLabelField] = useState(''), [parameters, setParameters] = useState(''), [timeFormat, setTimeFormat] = useState('iso8601')
  const [jobId, setJobId] = useState<string | null>(null)
  const job = useJob(jobId, () => {})
  const busy = !!jobId && (!job.data || !['succeeded', 'failed', 'cancelled'].includes(job.data.status))
  const peek = useMutation({ mutationFn: () => { const body = new FormData(); if (file) body.append('file', file); body.append('format', format); body.append('delimiter', delimiter); return request<components['schemas']['LogPreview']>(`/projects/${projectId}/action-logs/preview`, { method: 'POST', body }) }, onSuccess: p => { setPreview(p); setTimeField(p.fields[0] ?? ''); setLabelField(p.fields[1] ?? p.fields[0] ?? ''); setParameters('') } })
  const upload = useMutation({ mutationFn: () => { const body = new FormData(); if (file) body.append('file', file); body.append('format', format); body.append('mapping_json', JSON.stringify({ timestamp_field: timeField, label_field: labelField, parameters_field: parameters || null, timestamp_format: timeFormat, delimiter })); return request<Job>(`/projects/${projectId}/action-logs`, { method: 'POST', body }) }, onSuccess: j => { setJobId(j.id); state.selectJob(j.id) } })
  const logs = usePages<Log>(['logs', projectId], `/projects/${projectId}/action-logs`)
  return <section className="panel stack" aria-label="Импорт журнала действий"><h3>Импорт журнала действий</h3><p className="muted text-xs">CSV / JSON, UTF-8. Время capture = время log + поправка часов. Исследование и ручные привязки доступны в разделе «Исследование → Журнал действий».</p>
    <form className="form-row" onSubmit={e => { e.preventDefault(); peek.mutate() }}><label>Файл журнала<input type="file" accept=".csv,.json" onChange={e => { setFile(e.target.files?.[0] ?? null); setPreview(null) }} required /></label><label>Формат<select value={format} onChange={e => { setFormat(e.target.value); setPreview(null) }}><option value="csv">CSV</option><option value="json">JSON</option></select></label><label>Разделитель CSV<select value={delimiter} onChange={e => { setDelimiter(e.target.value); setPreview(null) }}><option value=",">Запятая</option><option value=";">Точка с запятой</option><option value={'\t'}>Табуляция</option></select></label><Button size="sm" variant="outline" disabled={!file || peek.isPending}>Посмотреть поля</Button></form>
    <ErrorMessage error={peek.error ?? upload.error ?? logs.error} />
    {preview && <div className="stack"><p className="notice">{preview.row_count} строк · поля: {preview.fields.join(', ')}</p><form className="form-row" onSubmit={e => { e.preventDefault(); upload.mutate() }}><label>Поле времени<select value={timeField} onChange={e => setTimeField(e.target.value)}>{preview.fields.map(f => <option key={f}>{f}</option>)}</select></label><label>Поле действия<select value={labelField} onChange={e => setLabelField(e.target.value)}>{preview.fields.map(f => <option key={f}>{f}</option>)}</select></label><label>Поле параметров<select value={parameters} onChange={e => setParameters(e.target.value)}><option value="">Не задано</option>{preview.fields.map(f => <option key={f}>{f}</option>)}</select></label><label>Формат времени<select value={timeFormat} onChange={e => setTimeFormat(e.target.value)}><option value="iso8601">ISO 8601 с timezone</option><option value="unix_s">Unix, секунды</option><option value="unix_ms">Unix, миллисекунды</option><option value="unix_ns">Unix, наносекунды</option></select></label><Button size="sm" disabled={busy || upload.isPending}>Импортировать журнал</Button></form></div>}
    <JobStatus job={job.data} />
    {logs.data?.pages.flatMap(p => p.items).map(log => <ClockForm key={`${log.id}:${log.clock_revision}`} log={log} />)}<More query={logs} />
  </section>
}
