import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { components } from '@/shared/api-types'
import { request, terminal, type Job } from '@/shared/api'
import { useWorkspaceState } from '@/shared/WorkspaceState'
import { useSelection } from '@/shared/store'
import { navigateSection } from '@/shared/navigation'
import { Button } from '@/shared/ui/button'
import { json, useJob, usePages } from './data'
import { ErrorMessage, JobStatus, More } from './Common'

type S = components['schemas']
type Corpus = S['StoredCorpus']
const families: Record<string, string> = { framing: 'Границы', structure: 'Постоянные области', entropy: 'Профиль байтов' }
const kinds: Record<string, string> = { fixed_framing: 'Фиксированный размер', length_framing: 'Поле длины', marker_framing: 'Парные маркеры', start_marker: 'Маркер начала', end_marker: 'Маркер конца', constant_region: 'Постоянная область', entropy_region: 'Энтропия блока' }
const statuses: Record<string, string> = { passed: 'Правило выполнено', failed: 'Противоречие', unknown: 'Неизвестно', ambiguous: 'Неоднозначно', not_applicable: 'Исключено' }

function Metrics({ value }: { value: S['InferenceMetrics'] }) {
  return <p className="notice">Уникальных совпадений: {value.matched}; противоречий: {value.contradicted}; неизвестных: {value.unknown}; неоднозначных: {value.ambiguous}; исключённых: {value.not_applicable}. Проверяемых: {value.matched + value.contradicted}. Соединений: {value.sessions}, записей: {value.captures}, разных длин: {value.distinct_lengths}. Единица: {value.unit}. Это выполнение правила, а не вероятность его истинности.</p>
}

export function InferencePanel({ projectId, navigate }: { projectId: string; navigate: (anchor: S['StreamRange']) => void }) {
  const client = useQueryClient()
  const [corpusId, setCorpusId] = useWorkspaceState('inference:corpus', '')
  const [holdoutIds, setHoldoutIds] = useWorkspaceState<string[]>('inference:holdout', [])
  const [reason, setReason] = useWorkspaceState('inference:reason', 'Дополнительная независимая запись пока не доступна')
  const [runId, setRunId] = useWorkspaceState('inference:run', '')
  const [candidateId, setCandidateId] = useWorkspaceState('inference:candidate', '')
  const [jobId, setJobId] = useWorkspaceState<string | null>('inference:job', null)
  const [advanced, setAdvanced] = useWorkspaceState('inference:advanced', '')
  const [targetCorpus, setTargetCorpus] = useState('')
  const [family, setFamily] = useState('')
  const [offset, setOffset] = useState(0)
  const [evidenceOffset, setEvidenceOffset] = useState(0)
  const [status, setStatus] = useState('')
  const [evaluationId, setEvaluationId] = useState('')
  const [draft, setDraft] = useWorkspaceState('inference:draft', '')
  const [draftCandidateId, setDraftCandidateId] = useWorkspaceState('inference:draftCandidate', '')
  const capabilities = useQuery({ queryKey: ['inference-capabilities'], queryFn: () => request<S['InferenceCapabilities']>('/inference/capabilities') })
  const corpora = usePages<Corpus>(['corpora', projectId], `/projects/${projectId}/corpora`)
  const corpus = useQuery({ queryKey: ['corpus', corpusId], queryFn: () => request<Corpus>(`/corpus-versions/${corpusId}`), enabled: !!corpusId })
  const runs = usePages<S['RunSummary']>(['inference-runs', projectId], `/projects/${projectId}/inference-runs`)
  const run = useQuery({ queryKey: ['inference-run', runId], queryFn: () => request<S['InferenceRun']>(`/inference-runs/${runId}`), enabled: !!runId })
  const currentness = useQuery({ queryKey: ['inference-currentness', runId], queryFn: () => request<S['InferenceCurrentness']>(`/inference-runs/${runId}/currentness`), enabled: !!runId })
  const candidates = useQuery({ queryKey: ['inference-candidates', runId, family, offset], queryFn: () => request<S['CandidateList']>(`/inference-runs/${runId}/candidates?offset=${offset}&limit=100${family ? `&family=${family}` : ''}`), enabled: !!runId })
  const candidate = useQuery({ queryKey: ['inference-candidate', candidateId], queryFn: () => request<S['InferenceCandidate']>(`/inference-candidates/${candidateId}`), enabled: !!candidateId })
  const evaluations = usePages<S['EvaluationRecord']>(['inference-evaluations', candidateId], `/inference-candidates/${candidateId}/evaluations`, !!candidateId)
  const evidence = useQuery({ queryKey: ['inference-evidence', candidateId, evaluationId, evidenceOffset, status], queryFn: () => request<S['EvidenceList']>(`/inference-candidates/${candidateId}/evidence?offset=${evidenceOffset}&limit=100${status ? `&status=${status}` : ''}${evaluationId ? `&evaluation_id=${evaluationId}` : ''}`), enabled: !!candidateId })
  function selectCandidate(id: string) { setCandidateId(id); setEvaluationId(''); setEvidenceOffset(0) }
  const job = useJob(jobId, completed => {
    if (completed.status !== 'succeeded') return
    if (typeof completed.result?.run_id === 'string') { setRunId(completed.result.run_id); selectCandidate(''); setOffset(0) }
    if (typeof completed.result?.evaluation_id === 'string') { setEvaluationId(completed.result.evaluation_id); setEvidenceOffset(0) }
    for (const key of ['inference-runs', 'inference-evaluations', 'inference-currentness']) void client.invalidateQueries({ queryKey: [key] })
  })
  const busy = !!jobId && (!job.data || !terminal(job.data.status))
  function started(j: Job) { setJobId(j.id); useSelection.getState().selectJob(j.id) }
  function specDocument() {
    if (advanced.trim()) return advanced
    if (!corpus.data || !capabilities.data) throw new Error('Дождитесь загрузки корпуса и настроек')
    const all = corpus.data.spec.capture_ids
    return JSON.stringify({ schema_version: 'inference-spec-1', corpus_version_id: corpusId, mode: 'discover', detectors: [{ family: 'framing' }, { family: 'structure' }, { family: 'entropy' }], split: { unit: 'capture', discovery_ids: all.filter(id => !holdoutIds.includes(id)), holdout_ids: all.filter(id => holdoutIds.includes(id)), holdout_unavailable_reason: holdoutIds.length ? null : reason }, sampling: { seed: 42 }, budget: capabilities.data.default_budget, search: capabilities.data.default_search }, null, 2)
  }
  const start = useMutation({ mutationFn: () => request<Job>(`/projects/${projectId}/inference-runs`, json({ document_json: specDocument(), parent_id: runId || null })), onSuccess: started })
  const evaluate = useMutation({ mutationFn: (holdout: boolean) => request<Job>(`/inference-candidates/${candidateId}/evaluations`, json(holdout ? { holdout: true } : { corpus_version_id: targetCorpus })), onSuccess: started })
  const compile = useMutation({ mutationFn: () => request<S['DraftResult']>(`/inference-candidates/${candidateId}/model-draft`, json({})), onSuccess: result => { setDraft(result.document_json ? JSON.stringify(JSON.parse(result.document_json), null, 2) : ''); setDraftCandidateId(result.candidate_id); save.reset() } })
  const save = useMutation({ mutationFn: () => request<S['StoredInterpretation']>(`/projects/${projectId}/interpretations`, json({ document_json: draft, parent_id: null })), onSuccess: () => { void client.invalidateQueries({ queryKey: ['interpretations', projectId] }) } })
  const list = candidates.data?.items ?? []
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: list.length, getScrollElement: () => scroll.current, estimateSize: () => 92, overscan: 5 })
  const evidenceScroll = useRef<HTMLDivElement>(null)
  const examples = evidence.data?.items ?? []
  const evidenceRows = useVirtualizer({ count: examples.length, getScrollElement: () => evidenceScroll.current, estimateSize: () => 110, overscan: 4 })
  const allCorpora = corpora.data?.pages.flatMap(p => p.items) ?? []
  const allRuns = runs.data?.pages.flatMap(p => p.items) ?? []
  const allEvaluations = evaluations.data?.pages.flatMap(p => p.items) ?? []
  const chosenEvaluation = allEvaluations.find(e => e.evaluation.id === evaluationId)
  const selected = candidate.data
  return <section className="panel stack" aria-label="Автоматический анализатор">
    <h3>Автоматический анализатор</h3>
    <p className="muted">Поиск предлагает несколько объяснений границ и полей длины. Постоянные области и энтропия относятся к выбранному варианту границ. Смысл команды и шифрование автоматически не устанавливаются.</p>
    <div className="form-row"><label>Корпус анализатора<select value={corpusId} onChange={e => { setCorpusId(e.target.value); setHoldoutIds([]); setAdvanced('') }}><option value="">Выберите сохранённую версию</option>{allCorpora.map(c => <option key={c.id} value={c.id}>{c.name} · {c.id.slice(0, 8)}</option>)}</select></label><More query={corpora} /><Button variant="outline" size="sm" onClick={() => navigateSection('validation')}>Настроить корпус</Button></div>
    {corpus.data && <fieldset className="stack"><legend>Записи для независимой проверки (holdout)</legend><p className="muted text-xs">Отмеченные записи не участвуют в подборе параметров. Остальные — discovery. Оставьте хотя бы одну запись для поиска.</p><div className="form-row">{corpus.data.spec.capture_ids.map(id => <label key={id} className="form-row"><input type="checkbox" checked={holdoutIds.includes(id)} onChange={e => { setAdvanced(''); setHoldoutIds(ids => e.target.checked ? [...ids, id] : ids.filter(v => v !== id)) }} />Запись {id.slice(0, 8)}</label>)}</div>{!holdoutIds.length && <label>Причина отсутствия holdout<input value={reason} onChange={e => setReason(e.target.value)} /></label>}</fieldset>}
    <details><summary>Настройки, допущения и защитные пределы</summary><p className="muted text-xs">Изменение JSON создаёт новый запуск. Для разбиения по соединениям, известных маркеров или исключённых областей укажите точный spec. Лимиты описывают работу программы.</p><Button variant="outline" size="sm" disabled={!corpus.data || !capabilities.data} onClick={() => setAdvanced(specDocument())}>Открыть настройки JSON</Button><label>Спецификация анализатора<textarea rows={14} value={advanced} onChange={e => setAdvanced(e.target.value)} placeholder="Стандартные настройки будут зафиксированы при запуске" /></label>{capabilities.data && <pre className="wrap-json">{JSON.stringify(capabilities.data.default_budget, null, 2)}</pre>}</details>
    <div className="form-row"><Button disabled={!corpusId || busy || start.isPending || (!advanced.trim() && (corpus.data?.spec.capture_ids.length === holdoutIds.length || (!holdoutIds.length && !reason.trim())))} onClick={() => start.mutate()}>Найти кандидатов</Button><small className="muted">Поиск выполняется локально в фоновом процессе.</small></div><JobStatus job={job.data} />
    <div className="form-row"><label>Запуск анализатора<select value={runId} onChange={e => { setRunId(e.target.value); selectCandidate(''); setOffset(0) }}><option value="">Выберите запуск</option>{allRuns.map(r => <option key={r.id} value={r.id}>{r.corpus_name} · {r.candidate_count} кандидатов · {r.id.slice(0, 8)}</option>)}</select></label><More query={runs} /><Button variant="outline" size="sm" disabled={!runId || currentness.isFetching} onClick={() => void currentness.refetch()}>Актуальность анализа</Button></div>
    {run.data && <>
      <p className="notice">{run.data.search_complete ? 'Заданный поиск завершён.' : 'Поиск ограничен; это не полный перебор.'} Проверено вариантов: {run.data.rule_trials}; сохранено кандидатов: {run.data.candidate_count}. Позиций потоков: {run.data.coverage.stream_bytes}; выбрано: {run.data.coverage.selected_bytes}; известных: {run.data.coverage.known_bytes}; недоступных: {run.data.coverage.unavailable_bytes}; неоднозначных: {run.data.coverage.ambiguous_bytes}; исключено: {run.data.coverage.excluded_bytes}; без объясняющих границ: {run.data.coverage.unframed_bytes}. Проверка holdout запускается отдельно после фиксации кандидата.</p>
      {run.data.snapshot.sources.some(c => !c.reconstruction_id || c.reconstruction_failures?.some(f => f.included)) && <p className="notice warning">Часть выбранных источников или направлений не восстановлена. Их размеры неизвестны и не входят в сумму позиций потоков; причины сохранены в диагностике запуска.</p>}
      <p className={`notice ${currentness.data?.stale ? 'warning' : ''}`}>{currentness.error ? 'Актуальность проверить не удалось.' : currentness.isFetching ? 'Проверка актуальности…' : currentness.data?.stale ? `Исторический результат: ${currentness.data.reasons.join('; ')}` : currentness.data ? 'Входы запуска актуальны.' : 'Актуальность ещё не проверена.'}</p>
      {run.data.outcomes.map(o => <p key={o.family} className="muted text-xs">{families[o.family] ?? o.family}: {o.outcome}; проверено {o.searched_units} ({o.searched_unit}); {o.unsearched_units ? 'остаётся непроверенное пространство' : 'непроверенных областей нет'}. {o.diagnostic}</p>)}
      <details><summary>Зафиксированные входы, версии и ограничения</summary><pre className="wrap-json">{JSON.stringify(run.data, null, 2)}</pre></details>
      <div className="form-row"><label>Семейство кандидатов<select value={family} onChange={e => { setFamily(e.target.value); setOffset(0) }}><option value="">Все семейства</option>{Object.entries(families).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label><small>Всего в фильтре: {candidates.data?.total ?? 0}. Фильтр не меняет покрытие.</small></div>
      <div ref={scroll} className="framing-list" role="list" aria-label="Кандидаты анализатора"><div style={{ height: rows.getTotalSize(), position: 'relative' }}>{rows.getVirtualItems().map(row => { const c = list[row.index]; return <button key={c.id} role="listitem" className={`framing-row ${candidateId === c.id ? 'selected' : ''}`} style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => selectCandidate(c.id)}><strong>{kinds[c.kind] ?? c.kind} · {c.metrics.matched}/{c.metrics.matched + c.metrics.contradicted}</strong><span>{c.rationale}</span><small>{c.dependency_ids.length ? 'Зависит от кандидата в границы · ' : ''}{c.compiler_support === 'not_compilable' ? 'Аналитическое наблюдение' : 'Доступен черновик модели'}</small></button> })}</div>{!list.length && <p className="muted p-3">{candidates.isLoading ? 'Загрузка кандидатов…' : 'Кандидатов нет. Проверьте диагностику, состав discovery и пределы поиска.'}</p>}</div>
      <div className="form-row"><Button size="sm" variant="outline" disabled={!offset || candidates.isFetching} onClick={() => setOffset(Math.max(0, offset - 100))}>Предыдущие кандидаты</Button><Button size="sm" variant="outline" disabled={candidates.data?.next_offset == null || candidates.isFetching} onClick={() => setOffset(candidates.data!.next_offset!)}>Следующие кандидаты</Button></div>
    </>}
    {selected && <div className="stack" aria-label="Карточка кандидата">
      <h4>{kinds[selected.rule.kind] ?? selected.rule.kind}</h4><Metrics value={selected.metrics} />
      <pre className="wrap-json">{JSON.stringify(selected.rule, null, 2)}</pre>
      <details><summary>Ранжирование, область и ограничения</summary><pre className="wrap-json">{JSON.stringify({ scope: selected.scope, ranking: selected.ranking, assumptions: selected.assumptions, limitations: selected.limitations, rule_sha256: selected.rule_sha256 }, null, 2)}</pre></details>
      {selected.dependency_ids.map(id => <Button key={id} size="sm" variant="outline" onClick={() => selectCandidate(id)}>Открыть исходный вариант границ {id.slice(0, 8)}</Button>)}
      {selected.compiler_support === 'not_compilable' ? <p className="notice">Создание самостоятельной модели не поддерживается: {selected.compiler_reason}</p> : <>
        <div className="form-row"><Button size="sm" variant="outline" disabled={!run.data?.snapshot.spec.split.holdout_ids.length || busy || evaluate.isPending} onClick={() => evaluate.mutate(true)}>Проверить на holdout</Button><label>Дополнительный корпус<select value={targetCorpus} onChange={e => setTargetCorpus(e.target.value)}><option value="">Выберите версию</option>{allCorpora.map(c => <option key={c.id} value={c.id}>{c.name} · {c.id.slice(0, 8)}</option>)}</select></label><Button size="sm" variant="outline" disabled={!targetCorpus || busy || evaluate.isPending} onClick={() => evaluate.mutate(false)}>Проверить фиксированное правило</Button></div>
        <Button size="sm" variant="outline" disabled={compile.isPending} onClick={() => compile.mutate()}>Создать черновик модели</Button>
      </>}
      <div className="form-row"><label>Свидетельства<select value={evaluationId} onChange={e => { setEvaluationId(e.target.value); setEvidenceOffset(0) }}><option value="">Discovery</option>{allEvaluations.map(e => <option key={e.evaluation.id} value={e.evaluation.id}>{e.target_side} · {e.evaluation.independence} · {e.evaluation.id.slice(0, 8)}</option>)}</select></label><More query={evaluations} /><label>Статус свидетельства<select value={status} onChange={e => { setStatus(e.target.value); setEvidenceOffset(0) }}><option value="">Все</option>{Object.entries(statuses).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label><small>Всего строк: {evidence.data?.total ?? 0}; повторы сохранены как источники и не увеличивают число уникальных совпадений.</small></div>
      {chosenEvaluation && <><Metrics value={chosenEvaluation.evaluation.metrics} /><p className="notice">{chosenEvaluation.complete ? 'Выбранная область проверена.' : 'Проверка ограничена ресурсами.'} Независимость: {chosenEvaluation.evaluation.independence}. {chosenEvaluation.evaluation.independence_reason}</p><details><summary>Область и версии проверки</summary><pre className="wrap-json">{JSON.stringify(chosenEvaluation, null, 2)}</pre></details></>}
      <div ref={evidenceScroll} className="framing-list" role="list" aria-label="Свидетельства кандидата"><div style={{ height: evidenceRows.getTotalSize(), position: 'relative' }}>{evidenceRows.getVirtualItems().map(row => { const e = examples[row.index]; return <button key={row.index} role="listitem" disabled={!e.anchor} className={`framing-row ${e.status === 'failed' ? 'failed' : ''}`} style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => e.anchor && navigate(e.anchor)}><strong>{statuses[e.status]} · {e.anchor ? `[${e.anchor.byte_range.start}, ${e.anchor.byte_range.end})` : 'Без диапазона'}</strong><span>{e.diagnostic}</span><small>{e.sources.length} исходных диапазонов · {e.preview_hex} · Открыть байты и пакеты</small></button> })}</div></div>
      <div className="form-row"><Button size="sm" variant="outline" disabled={!evidenceOffset || evidence.isFetching} onClick={() => setEvidenceOffset(Math.max(0, evidenceOffset - 100))}>Предыдущие свидетельства</Button><Button size="sm" variant="outline" disabled={evidence.data?.next_offset == null || evidence.isFetching} onClick={() => setEvidenceOffset(evidence.data!.next_offset!)}>Следующие свидетельства</Button></div>
      {draft && draftCandidateId === candidateId && <div className="stack"><label>Черновик исполняемой модели<textarea rows={18} value={draft} onChange={e => setDraft(e.target.value)} /></label><p className="muted">Границы перенесены точно. Байты тела остаются без семантической расшифровки. Сохранение создаст отдельную новую версию.</p><Button size="sm" disabled={save.isPending} onClick={() => save.mutate()}>Сохранить черновик как новую модель</Button>{save.data && <p className="notice">Сохранена версия {save.data.id}. Выберите её в разделе «Проверка» для полного корпуса.</p>}</div>}
    </div>}
    <ErrorMessage error={capabilities.error ?? corpora.error ?? corpus.error ?? start.error ?? runs.error ?? run.error ?? currentness.error ?? candidates.error ?? candidate.error ?? evidence.error ?? evaluations.error ?? evaluate.error ?? compile.error ?? save.error ?? job.error} />
  </section>
}
