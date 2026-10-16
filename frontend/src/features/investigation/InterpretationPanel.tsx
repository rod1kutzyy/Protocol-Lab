import { useWorkspaceState } from '@/shared/WorkspaceState'
import { useEffect, useRef, useState } from 'react'
import Editor, { type OnMount } from '@monaco-editor/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type * as Monaco from 'monaco-editor'
import '@/shared/monaco'
import { request, terminal, type Job } from '@/shared/api'
import type { components } from '@/shared/api-types'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { json, useJob, usePages, type Stream } from './data'
import { ErrorMessage, JobStatus, More, TechnicalLimitNotice } from './Common'
import { sampleModel, modelSignature, formatModel, replaceFraming } from './interpretation-config'

type Version = components['schemas']['StoredInterpretation']
type Run = components['schemas']['DecodeRun']
type Summary = components['schemas']['MessageSummary']
type Result = components['schemas']['MessageResult']
type Check = components['schemas']['ModelCheck']
type FramingRun = components['schemas']['RunView']
const statuses = { passed: 'Правила выполнены', failed: 'Проверка нарушена', unknown: 'Неизвестно', ambiguous: 'Неоднозначно', not_applicable: 'Не размечено' }
const kinds = { int: 'Целое', bytes: 'Байты HEX', delimited_bytes: 'Байты до разделителя', array: 'Массив: число элементов', switch: 'Вариант: значение селектора' }
const reasons: Record<string, string> = { uninterpreted: 'Байты не описаны моделью', gap: 'Байты отсутствуют в записи', truncated: 'Усечённый пакет', ambiguous: 'Конфликтующие варианты байтов' }

export function InterpretationPanel({ stream, framing, onNavigate }: { stream: Stream; framing: FramingRun; onNavigate: (anchor: components['schemas']['StreamRange']) => void }) {
  const state = useSelection(), client = useQueryClient()
  const [text, setText] = useWorkspaceState(`interpretation:${framing.id}:text`, () => sampleModel(framing.spec))
  const [versionId, setVersionId] = useWorkspaceState<string | null>(`interpretation:${framing.id}:versionId`, null)
  const [runId, setRunId] = useWorkspaceState<string | null>(`interpretation:${framing.id}:runId`, null), [pieceId, setPieceId] = useWorkspaceState<string | null>(`interpretation:${framing.id}:pieceId`, null)
  const [jobId, setJobId] = useWorkspaceState<string | null>(`interpretation:${framing.id}:jobId`, null), [localError, setLocalError] = useState<Error | null>(null)
  const [mounted, setMounted] = useState(false)
  const editor = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null), monaco = useRef<typeof Monaco | null>(null)
  const path = `inmemory://protocol-lab/${framing.id}/interpretation.json`
  const schema = useQuery({ queryKey: ['interpretation-schema'], queryFn: () => request<Record<string, unknown>>('/interpretations/schema') })
  const versions = usePages<Version>(['interpretations', state.projectId], `/projects/${state.projectId}/interpretations`, !!state.projectId)
  const selectedVersion = useQuery({ queryKey: ['interpretation-version', versionId], queryFn: () => request<Version>(`/interpretation-versions/${versionId}`), enabled: !!versionId })
  const check = useMutation({ mutationFn: (document: string) => request<Check>('/interpretations/check', json({ document_json: document })) })
  const save = useMutation({ mutationFn: (input: { document: string; parentId: string | null }) => request<Version>(`/projects/${state.projectId}/interpretations`, json({ document_json: input.document, parent_id: input.parentId })), onSuccess: v => { setVersionId(v.id); setText(formatModel(v.document_json)); client.setQueryData(['interpretation-version', v.id], v); void client.invalidateQueries({ queryKey: ['interpretations', state.projectId] }); void client.invalidateQueries({ queryKey: ['validation-currentness'] }) } })
  const job = useJob(jobId, j => { if (j.status === 'succeeded' && typeof j.result?.run_id === 'string') { setRunId(j.result.run_id); setPieceId(null) } })
  const busy = !!jobId && (!job.data || !terminal(job.data.status))
  const apply = useMutation({ mutationFn: () => request<Job>(`/framing-runs/${framing.id}/interpretations`, json({ version_id: versionId })), onSuccess: j => { setJobId(j.id); state.selectJob(j.id) } })
  const rebuild = useMutation({ mutationFn: () => { const document = JSON.parse(selectedVersion.data!.document_json); return request<Job>(`/streams/${stream.id}/framing`, json(document.framing)) }, onSuccess: j => { state.selectJob(j.id); setRebuildJobId(j.id) } })
  const [rebuildJobId, setRebuildJobId] = useWorkspaceState<string | null>(`interpretation:${framing.id}:rebuildJobId`, null)
  const rebuildJob = useJob(rebuildJobId, () => {})
  const runs = usePages<Run>(['interpretation-runs', framing.id], `/framing-runs/${framing.id}/interpretations`)
  const selectedRun = useQuery({ queryKey: ['interpretation-run', runId], queryFn: () => request<Run>(`/interpretation-runs/${runId}`), enabled: !!runId })
  const summaries = usePages<Summary>(['interpretation-results', runId], `/interpretation-runs/${runId}/results`, !!runId)
  const result = useQuery({ queryKey: ['interpretation-result', runId, pieceId], queryFn: () => request<Result>(`/interpretation-runs/${runId}/results/${pieceId}`), enabled: !!runId && !!pieceId })
  const items = summaries.data?.pages.flatMap(p => p.items) ?? [], loadedVersions = versions.data?.pages.flatMap(p => p.items) ?? [], loadedRuns = runs.data?.pages.flatMap(p => p.items) ?? []
  const versionOptions = selectedVersion.data && !loadedVersions.some(v => v.id === versionId) ? [...loadedVersions, selectedVersion.data] : loadedVersions
  const runOptions = selectedRun.data && !loadedRuns.some(r => r.id === runId) ? [...loadedRuns, selectedRun.data] : loadedRuns
  const messageScroll = useRef<HTMLDivElement>(null), fieldScroll = useRef<HTMLDivElement>(null), unknownScroll = useRef<HTMLDivElement>(null)
  const messages = useVirtualizer({ count: items.length, getScrollElement: () => messageScroll.current, estimateSize: () => 76, overscan: 4 })
  const fields = result.data?.fields ?? [], unknown = result.data?.unknown_ranges ?? []
  const fieldRows = useVirtualizer({ count: fields.length, getScrollElement: () => fieldScroll.current, estimateSize: () => 64, overscan: 4 })
  const unknownRows = useVirtualizer({ count: unknown.length, getScrollElement: () => unknownScroll.current, estimateSize: () => 64, overscan: 4 })
  const dirty = (() => { try { return !selectedVersion.data || modelSignature(text) !== modelSignature(selectedVersion.data.document_json) } catch { return true } })()
  const mismatch = (() => { try { return !!selectedVersion.data && modelSignature(JSON.stringify(JSON.parse(selectedVersion.data.document_json).framing)) !== modelSignature(JSON.stringify(framing.spec)) } catch { return true } })()
  const issues = check.variables === text ? check.data?.issues ?? [] : []
  const onMount: OnMount = (instance, runtime) => {
    editor.current = instance; monaco.current = runtime
    // Select the model, rather than the small native textarea used for IME input.
    instance.addAction({ id: 'protocol-lab.select-model', label: 'Select entire model', keybindings: [runtime.KeyMod.CtrlCmd | runtime.KeyCode.KeyA], run: current => { const model = current.getModel(); if (model) current.setSelection(model.getFullModelRange()) } })
    setMounted(true)
  }
  useEffect(() => {
    if (mounted && schema.data && monaco.current) monaco.current.languages.json.jsonDefaults.setDiagnosticsOptions({ validate: true, allowComments: false, enableSchemaRequest: false, schemas: [{ uri: 'urn:protocol-lab:interpretation-1', fileMatch: [path], schema: schema.data }] })
  }, [schema.data, path, mounted])
  useEffect(() => {
    const model = editor.current?.getModel(), runtime = monaco.current
    if (!model || !runtime) return
    runtime.editor.setModelMarkers(model, 'protocol-schema', issues.map(issue => {
      const name = issue.path.split('.').filter(p => p && !/^\d+$/.test(p)).at(-1)
      const offset = name ? Math.max(0, text.indexOf(JSON.stringify(name))) : 0
      const pos = model.getPositionAt(offset)
      return { severity: runtime.MarkerSeverity.Error, message: `${issue.path || 'Модель'}: ${issue.message}`, startLineNumber: pos.lineNumber, endLineNumber: pos.lineNumber, startColumn: pos.column, endColumn: pos.column + (name?.length ?? 1) + 2 }
    }))
  }, [issues, text, mounted])
  function navigate(anchor: components['schemas']['StreamRange']) {
    onNavigate(anchor)
  }
  return <section className="stack interpretation-panel" aria-label="Модель протокола"><h3>Интерпретация — поля и правила</h3>
    <p className="muted text-xs">Здесь выполняются разбор полей и локальные проверки, включая checksum/CRC. Межсообщенческие правила corpus_checks выполняются в разделе «Проверка корпуса».</p>
    <p className="muted text-xs">Значения получены исполнением модели. Имена полей задаёт инженер; смысл поля остаётся предположением. Все смещения относятся к исходному потоку, [start, end).</p>
    <div className="form-row"><label>Версия модели<select value={versionId ?? ''} disabled={check.isPending || save.isPending} onChange={e => { const v = versionOptions.find(v => v.id === e.target.value); setVersionId(v?.id ?? null); setText(v ? formatModel(v.document_json) : sampleModel(framing.spec)); check.reset() }}><option value="">Новая модель</option>{versionOptions.map(v => <option key={v.id} value={v.id}>{JSON.parse(v.document_json).name} · {v.id.slice(0, 8)}</option>)}</select></label><More query={versions} /></div>
    <div className="form-row"><Button size="sm" variant="outline" disabled={check.isPending || save.isPending} onClick={() => { setText(sampleModel(framing.spec)); check.reset() }}>Пример: исходные байты</Button><Button size="sm" variant="outline" disabled={framing.spec.rule.kind !== 'length' || check.isPending || save.isPending} onClick={() => { try { setText(sampleModel(framing.spec, 'length')); check.reset() } catch (e) { setLocalError(e as Error) } }}>Пример: поле длины</Button><Button size="sm" variant="outline" disabled={check.isPending || save.isPending} onClick={() => { setText(sampleModel(framing.spec, 'variants')); check.reset() }}>Пример: массив и варианты</Button><Button size="sm" variant="outline" disabled={check.isPending || save.isPending} onClick={() => { try { setText(replaceFraming(text, framing.spec)); check.reset(); setLocalError(null) } catch (e) { setLocalError(e as Error) } }}>Использовать выбранный фрейминг</Button></div>
    <div className="model-editor"><Editor height="420px" path={path} language="json" value={text} onChange={v => { setText(v ?? ''); setLocalError(null) }} onMount={onMount} options={{ readOnly: check.isPending || save.isPending, minimap: { enabled: false }, automaticLayout: true, scrollBeyondLastLine: false, tabSize: 2 }} loading={<p>Загрузка локального редактора…</p>} /></div>
    <div className="form-row"><Button size="sm" variant="outline" disabled={check.isPending || save.isPending} onClick={() => check.mutate(text)}>Проверить модель</Button><Button size="sm" disabled={check.isPending || save.isPending || !dirty} onClick={() => { check.mutate(text, { onSuccess: c => { if (c.valid) save.mutate({ document: text, parentId: versionId }) } }) }}>Сохранить новую версию</Button><span className="muted text-xs">{dirty ? 'В редакторе есть несохранённые изменения.' : `Сохранена версия ${versionId?.slice(0, 8)}.`}</span></div>
    {check.variables === text && check.data && <div role="status" className={`notice ${check.data.valid ? '' : 'error'}`}>{check.data.valid ? 'Модель соответствует схеме и правилам ссылок.' : <ul>{issues.map((issue, i) => <li key={i}>{issue.path || 'Модель'}: {issue.message}</li>)}</ul>}</div>}
    {mismatch && <p className="notice">Сохранённая модель использует другие настройки фрейминга. Используйте выбранный фрейминг и сохраните новую версию, либо постройте границы по сохранённой модели.</p>}
    <div className="form-row"><Button size="sm" disabled={!versionId || dirty || mismatch || busy || apply.isPending} onClick={() => apply.mutate()}>Разобрать сообщения</Button>{mismatch && <Button size="sm" variant="outline" disabled={dirty || rebuild.isPending || (!!rebuildJob.data && !terminal(rebuildJob.data.status))} onClick={() => rebuild.mutate()}>Построить фрейминг модели</Button>}</div>
    <JobStatus job={job.data} /><JobStatus job={rebuildJob.data} />{rebuildJob.data?.status === 'succeeded' && <p className="notice">Фрейминг построен. Выберите его в списке результатов выше, затем откройте сохранённую модель.</p>}
    <ErrorMessage error={localError ?? schema.error ?? versions.error ?? selectedVersion.error ?? check.error ?? save.error ?? apply.error ?? rebuild.error ?? rebuildJob.error ?? job.error ?? runs.error ?? selectedRun.error ?? summaries.error ?? result.error} />
    <div className="form-row"><label>Сохранённый разбор<select value={runId ?? ''} onChange={e => { setRunId(e.target.value || null); setPieceId(null) }}><option value="">Выберите разбор</option>{runOptions.map(r => <option key={r.id} value={r.id}>Модель {r.version_id.slice(0, 8)} · результат {r.id.slice(0, 8)}</option>)}</select></label><More query={runs} /></div>
    {selectedRun.data && <><p className="notice">Разбор относится к модели {selectedRun.data.version_id.slice(0, 8)} и фреймингу {selectedRun.data.framing_run_id.slice(0, 8)}. Это исполнение на выбранном потоке; весь корпус проверяется в разделе «Проверка». {Object.entries(selectedRun.data.counts).map(([k, n]) => `${statuses[k as keyof typeof statuses]}: ${n}`).join(' · ')}</p>
      <div ref={messageScroll} className="framing-list" role="list" aria-label="Результаты разбора"><div style={{ height: messages.getTotalSize(), position: 'relative' }}>{messages.getVirtualItems().map(row => { const item = items[row.index], r = item.anchor.byte_range; return <button role="listitem" key={item.piece_id} className={`framing-row ${pieceId === item.piece_id ? 'selected' : ''}`} style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => setPieceId(item.piece_id)}><strong>[{r.start}, {r.end}) · {statuses[item.status]}</strong><span>{item.diagnostic}</span><small>Полей: {item.field_count}. Неразобранных диапазонов: {item.unknown_range_count}. Открыть значения</small></button> })}</div></div><More query={summaries} />
      {result.data && <div className="stack"><div className="form-row"><h4>Извлечённые значения</h4><Button size="sm" variant="outline" onClick={() => navigate(result.data!.anchor)}>Сообщение → bytes и пакеты</Button></div><p className="muted text-xs">Целые показаны точными десятичными строками. HEX содержит до 64 байтов предпросмотра; полный диапазон доступен по клику.</p>
        <div className="decoded-list" ref={fieldScroll} role="list" aria-label="Поля модели"><div style={{ height: fieldRows.getTotalSize(), position: 'relative' }}>{fieldRows.getVirtualItems().map(row => { const f = fields[row.index]; return <button role="listitem" key={f.path} disabled={!f.anchor} className="framing-row" style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => f.anchor && navigate(f.anchor)}><strong>{f.path} = {f.value || '(пусто)'}{f.preview_truncated ? '…' : ''}</strong><small>{kinds[f.kind]} · [{f.offset}, {f.offset + f.length}) · {f.length} bytes{f.anchor ? ' · Открыть источник' : ' · Пустое поле'}</small></button> })}</div>{!fields.length && <p className="muted p-3">Нет извлечённых полей.</p>}</div>
        <TechnicalLimitNotice limit={result.data.technical_limit} />
        <h4>Неизвестные и неописанные участки</h4>{unknown.length ? <div className="decoded-list" ref={unknownScroll} role="list" aria-label="Неизвестные участки"><div style={{ height: unknownRows.getTotalSize(), position: 'relative' }}>{unknownRows.getVirtualItems().map(row => { const u = unknown[row.index], r = u.anchor.byte_range; return <button role="listitem" key={r.start} className="framing-row leftover" style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => navigate(u.anchor)}><strong>[{r.start}, {r.end})</strong><small>{reasons[u.reason] ?? u.reason} · Открыть bytes и источники</small></button> })}</div></div> : <p className="muted">Неразобранных участков нет.</p>}
      </div>}
    </>}
  </section>
}
