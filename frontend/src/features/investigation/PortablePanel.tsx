import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { components } from '@/shared/api-types'
import { request, terminal, type Job } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { ErrorMessage, JobStatus, More } from './Common'
import { json, useJob, usePages } from './data'

type Version = components['schemas']['StoredInterpretation']
type Run = components['schemas']['ValidationRunSummary']

export function RestoreProject() {
  const [file, setFile] = useState<File | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)
  const client = useQueryClient()
  const state = useSelection()
  const job = useJob(jobId, result => { if (result.status === 'succeeded' && typeof result.result?.project_id === 'string') { void client.invalidateQueries({ queryKey: ['projects'] }); state.openProject(result.result.project_id) } })
  const restore = useMutation({ mutationFn: () => { const body = new FormData(); if (file) body.append('file', file); return request<Job>('/projects/restore', { method: 'POST', body }) }, onSuccess: result => { setJobId(result.id); state.selectJob(result.id) } })
  const busy = restore.isPending || !!jobId && (!job.data || !terminal(job.data.status))
  return <section className="stack" aria-label="Восстановление проекта"><h3>Перенос проекта</h3><label>Архив проекта ZIP<input type="file" accept=".zip" onChange={e => setFile(e.target.files?.[0] ?? null)} /></label><Button size="sm" variant="outline" disabled={!file || busy} onClick={() => restore.mutate()}>Восстановить проект</Button><p className="muted text-xs">Проверяются версия и SHA-256. Существующий проект с тем же ID сохраняется; повторное восстановление сообщит о совпадении.</p><JobStatus job={job.data} /><ErrorMessage error={restore.error ?? job.error} /></section>
}

export function PortablePanel({ projectId }: { projectId: string }) {
  const [jobId, setJobId] = useState<string | null>(null)
  const [version, setVersion] = useState('')
  const [run, setRun] = useState('')
  const [verified, setVerified] = useState(false)
  const state = useSelection()
  const models = usePages<Version>(['interpretations', projectId], `/projects/${projectId}/interpretations`)
  const runs = usePages<Run>(['validation-runs', projectId], `/projects/${projectId}/validation-runs`)
  const job = useJob(jobId, result => { if (result.result?.outcome === 'verified') setVerified(true) })
  const operation = useMutation({ mutationFn: (kind: string) => request<Job>(`/projects/${projectId}/operations/${kind}`, json({})), onSuccess: (result, kind) => { if (kind === 'verify') setVerified(false); setJobId(result.id); state.selectJob(result.id) } })
  const exportRun = useMutation({ mutationFn: () => request<Job>(`/validation-runs/${run}/export`, json({})), onSuccess: result => { setJobId(result.id); state.selectJob(result.id) } })
  // Opening a project starts a background integrity check of the complete registered state.
  useEffect(() => { operation.mutate('verify') }, [projectId])
  const busy = operation.isPending || exportRun.isPending || !!jobId && (!job.data || !terminal(job.data.status))
  const result = job.data?.status === 'succeeded' ? job.data.result : null
  const download = typeof result?.download_url === 'string' ? result.download_url : null
  return <section className="panel stack" aria-label="Сохранение и экспорт проекта">
    <h3>Сохранение, перенос и отчёт</h3>
    <p className="notice">{verified ? 'Полное состояние проверено при открытии: версии формата и контрольные суммы файлов совпадают.' : 'При открытии выполняется проверка полного состояния. Результат и возможные ошибки показаны ниже.'}</p>
    <div className="form-row"><Button variant="outline" disabled={busy} onClick={() => operation.mutate('verify')}>Проверить целостность</Button><Button disabled={busy} onClick={() => operation.mutate('save')}>Сохранить полный снимок</Button><Button disabled={busy} onClick={() => operation.mutate('export')}>Экспортировать проект ZIP</Button><Button variant="outline" disabled={busy} onClick={() => operation.mutate('report')}>Сформировать Markdown-отчёт</Button></div>
    <p className="muted text-xs">Снимок включает все версии, исходники, provenance, журналы действий, наблюдения, гипотезы, настройки и результаты. Он сохраняется в каталоге проекта. Архив восстанавливается в локальном PostgreSQL через «Перенос проекта».</p>
    <div className="form-row"><label>Версия интерпретации для JSON<select value={version} onChange={e => setVersion(e.target.value)}><option value="">Выберите версию</option>{models.data?.pages.flatMap(p => p.items).map(v => <option key={v.id} value={v.id}>{v.id.slice(0, 8)} · {v.content_sha256.slice(0, 12)}</option>)}</select></label>{version && <a className="text-sm underline" href={`/api/v1/interpretation-versions/${version}/export`} download>Скачать интерпретацию JSON</a>}<More query={models} /></div>
    <div className="form-row"><label>Запуск проверки для JSON<select value={run} onChange={e => setRun(e.target.value)}><option value="">Выберите запуск</option>{runs.data?.pages.flatMap(p => p.items).map(v => <option key={v.id} value={v.id}>{v.corpus_name} · {v.id.slice(0, 8)}</option>)}</select></label><Button variant="outline" disabled={!run || busy} onClick={() => exportRun.mutate()}>Экспортировать результаты JSON</Button><More query={runs} /></div>
    <JobStatus job={job.data} />
    {download && <a className="underline" href={download} download>Скачать {typeof result?.filename === 'string' ? result.filename : 'готовый файл'}</a>}
    {typeof result?.checkpoint === 'string' && <p className="notice">Полный снимок сохранён: {result.checkpoint}</p>}
    <ErrorMessage error={operation.error ?? exportRun.error ?? job.error ?? models.error ?? runs.error} />
  </section>
}
