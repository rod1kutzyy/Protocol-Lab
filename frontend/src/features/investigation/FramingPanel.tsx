import { useWorkspaceState } from '@/shared/WorkspaceState'
import { lazy, Suspense, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { components } from '@/shared/api-types'
import { request, type Job } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { WorkspaceScreen } from '@/shared/WorkspaceScreen'
import { Button } from '@/shared/ui/button'
import { json, useJob, usePages, type Stream } from './data'
import { ErrorMessage, JobStatus, More } from './Common'
const InterpretationPanel = lazy(() => import('./InterpretationPanel').then(m => ({ default: m.InterpretationPanel })))
import { framingSpec, framingSignature, initialFraming, type FramingDraft } from './framing-config'

type Run = components['schemas']['RunView']
type Piece = components['schemas']['Piece']
const modeNames = { manual: 'Ручные границы', fixed: 'Фиксированный размер', length: 'Поле длины', markers: 'Начальный / конечный маркер' }
const reasons: Record<string,string> = {
  before_configured_start: 'До заданного начала', not_manually_framed: 'Не размечено вручную',
  incomplete_fixed_message: 'Недостаточно позиций для полного сообщения',
  incomplete_length_header: 'Поле длины не помещается в остатке',
  unknown_length_header_no_resynchronization: 'Поле длины неизвестно; выравнивание дальше не угадывается',
  invalid_length_no_resynchronization: 'Недопустимая длина; выравнивание дальше не угадывается',
  max_message_bytes_exceeded_no_resynchronization: 'Размер превышает технический лимит; правило не опровергнуто',
  incomplete_length_message: 'Сообщение заявленной длины выходит за конец потока',
  unknown_bytes_marker_barrier: 'Неизвестные байты разрывают поиск маркеров',
  start_marker_not_found: 'Начальный маркер не найден', before_start_marker: 'До начального маркера',
  end_marker_not_found_or_limit_exceeded: 'Конечный маркер не найден до пропуска, конца или лимита',
  end_marker_search_limit_exceeded: 'Поиск конечного маркера остановлен техническим лимитом размера сообщения',
  end_marker_search_interrupted_by_unknown_bytes: 'Поиск конечного маркера прерван неизвестными байтами',
  end_marker_not_found_before_stream_end: 'Конечный маркер не найден до конца доступного потока',
  manual_boundary_hypothesis: 'Границы заданы инженером', fixed_boundary_rule: 'Границы по фиксированному размеру',
  length_boundary_rule: 'Границы по полю длины', explicit_markers_included: 'Оба маркера включены в сообщение',
}
const statuses = { known: 'Известные байты', incomplete: 'Есть пропуски / усечение', ambiguous: 'Есть конфликтующие байты', mixed: 'Есть пропуски и конфликты' }
export function FramingPanel({ stream, onNavigate }: { stream: Stream; onNavigate: (anchor: components['schemas']['StreamRange']) => void }) {
  const [tab, setTab] = useWorkspaceState<'framing' | 'fields'>(`framing:${stream.id}:tab`, 'framing')
  const [draft, setDraft] = useWorkspaceState<FramingDraft>(`framing:${stream.id}:draft`, initialFraming)
  const [jobId, setJobId] = useWorkspaceState<string | null>(`framing:${stream.id}:jobId`, null), [runId, setRunId] = useWorkspaceState<string | null>(`framing:${stream.id}:runId`, null)
  const [filter, setFilter] = useWorkspaceState(`framing:${stream.id}:filter`, ''), [formError, setFormError] = useState<Error | null>(null)
  const state = useSelection()
  const change = (key: keyof FramingDraft, value: string) => setDraft(d => ({ ...d, [key]: value }))
  const job = useJob(jobId, completed => { if (completed.status === 'succeeded' && typeof completed.result?.run_id === 'string') setRunId(completed.result.run_id) })
  const busy = !!jobId && (!job.data || !['succeeded','failed','cancelled'].includes(job.data.status))
  const run = useMutation({ mutationFn: () => request<Job>(`/streams/${stream.id}/framing`, json(framingSpec(draft, stream.extent))), onSuccess: j => { setJobId(j.id); state.selectJob(j.id); setFormError(null) } })
  const runs = usePages<Run>(['framing-runs', stream.id], `/streams/${stream.id}/framing`)
  const selected = useQuery({ queryKey: ['framing-run', runId], queryFn: () => request<Run>(`/framing-runs/${runId}`), enabled: !!runId })
  const loaded = runs.data?.pages.flatMap(p => p.items) ?? []
  const options = selected.data && !loaded.some(r => r.id === selected.data?.id) ? [...loaded, selected.data] : loaded
  const pieces = usePages<Piece>(['framing-pieces', runId], `/framing-runs/${runId}/pieces`, !!runId)
  // Filtering is only over loaded rows; expose that scope instead of hiding coverage.
  const all = pieces.data?.pages.flatMap(p => p.items) ?? []
  const items = all.filter(p => !filter || p.kind === filter)
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: items.length, getScrollElement: () => scroll.current, estimateSize: () => 74, overscan: 5 })
  const active = state.range?.streamId === stream.id ? state.range : null
  const edited = (() => { try { return !!selected.data && framingSignature(framingSpec(draft, stream.extent)) !== framingSignature(selected.data.spec) } catch { return true } })()
  function number(label: string, key: keyof FramingDraft, minimum: number, maximum?: number) {
    return <label>{label}<input type="number" min={minimum} max={maximum} value={draft[key]} onChange={e => change(key, e.target.value)} required /></label>
  }
  return <section className="panel stack" aria-label="Фрейминг потока"><h3>Модель протокола</h3>
    <nav className="tool-navigation" aria-label="Инструменты модели"><Button variant={tab === 'framing' ? 'default' : 'outline'} aria-pressed={tab === 'framing'} onClick={() => setTab('framing')}>Границы сообщений</Button><Button variant={tab === 'fields' ? 'default' : 'outline'} aria-pressed={tab === 'fields'} onClick={() => setTab('fields')}>Поля и правила</Button></nav>
    <p className="muted text-xs">Правило задаёт предполагаемые границы, а не смысл полей. Пакеты TCP не определяют границы сообщений. Наблюдения остаются на исходных диапазонах.</p>
    <ErrorMessage error={formError ?? run.error ?? job.error ?? runs.error ?? selected.error ?? pieces.error} /><JobStatus job={job.data} />
    <div className="form-row"><label>Сохранённый результат фрейминга<select value={runId ?? ''} onChange={e => setRunId(e.target.value || null)}><option value="">Выберите результат</option>{options.map(r => <option value={r.id} key={r.id}>{modeNames[r.spec.rule.kind]} · {r.message_count} сообщений · {r.id.slice(0,8)}</option>)}</select></label><More query={runs} /></div>
    <WorkspaceScreen active={tab === 'framing'} className="tool-screen">
    <form className="stack" onSubmit={e => { e.preventDefault(); run.mutate() }}>
      <div className="form-row"><label>Режим фрейминга<select value={draft.kind} onChange={e => change('kind', e.target.value)}>{Object.entries(modeNames).map(([kind,name]) => <option value={kind} key={kind}>{name}</option>)}</select></label>
        {draft.kind !== 'manual' && number('Начало фрейминга', 'start', 0, stream.extent)}{number('Лимит размера сообщения, bytes', 'maxBytes', 1, 16777216)}</div>
      {draft.kind === 'fixed' && <div className="form-row">{number('Фиксированный размер, bytes', 'size', 1, 16777216)}</div>}
      {draft.kind === 'manual' && <div className="stack"><label>Ручные диапазоны [начало, конец)<textarea value={draft.ranges} onChange={e => change('ranges',e.target.value)} placeholder={'0:5\n5:10'} rows={4} /></label><Button type="button" size="sm" variant="outline" disabled={!active} onClick={() => active && change('ranges', `${draft.ranges.trim()}${draft.ranges.trim() ? '\n' : ''}${active.start}:${active.end}`)}>Добавить выделение как сообщение</Button><p className="muted text-xs">По одному диапазону на строке, в порядке потока, без перекрытий. Остальные байты остаются неразмеченными.</p></div>}
      {draft.kind === 'length' && <div className="stack"><div className="form-row">{number('Смещение поля от начала сообщения', 'offset', 0, 65536)}<label>Ширина поля, bytes<select value={draft.width} onChange={e => change('width',e.target.value)}>{[1,2,4,8].map(n => <option key={n}>{n}</option>)}</select></label><label>Порядок байтов<select value={draft.endian} onChange={e => change('endian',e.target.value)}><option value="big">Big endian</option><option value="little">Little endian</option></select></label>{number('Множитель длины','multiplier',1,65536)}{number('Поправка длины','adjustment',-16777216,16777216)}</div><p className="notice">Полный размер сообщения = значение поля × множитель + поправка. Размер включает заголовок; поле должно помещаться в сообщение. Значение поля — беззнаковое целое.</p></div>}
      {draft.kind === 'markers' && <div className="stack"><div className="form-row"><label>Начальный маркер HEX<input value={draft.startHex} onChange={e => change('startHex',e.target.value)} placeholder="AA BB" required /></label><label>Конечный маркер HEX<input value={draft.endHex} onChange={e => change('endHex',e.target.value)} placeholder="CC DD" required /></label></div><p className="muted text-xs">Маркеры включаются в сообщение. Первый конец после начала завершает сообщение. Поиск не пересекает неизвестные или конфликтующие байты; escaping и вложенность не предполагаются.</p></div>}
      <div className="form-row"><Button size="sm" disabled={!stream.extent || busy || run.isPending}>Построить предварительный просмотр</Button><span className="muted text-xs">Успешный результат сохраняется как неизменяемая версия. Отмена оставляет прежний результат.</span></div>
    </form>
    {selected.data && <div className="stack"><p className="notice">Сообщений: {selected.data.message_count}. Неразмеченных позиций: {selected.data.leftover_bytes}. Позиций в диапазонах с неопределёнными данными: {selected.data.uncertain_bytes}. Размер потока: {selected.data.extent}. Версия: {selected.data.id.slice(0,8)}.</p>
      {edited && <p className="notice">Просмотр относится к сохранённым настройкам ниже. Изменения формы применятся после нового построения.</p>}
      <details><summary>Настройки выбранного результата</summary><pre className="wrap-json">{JSON.stringify(selected.data.spec,null,2)}</pre></details>
      <div className="form-row"><label>Показывать среди загруженных диапазонов<select value={filter} onChange={e => setFilter(e.target.value)}><option value="">Все диапазоны</option><option value="message">Сообщения</option><option value="leftover">Остатки</option></select></label><small className="muted">Загружено {all.length} диапазонов. Сообщения и остатки вместе покрывают весь поток; [start,end).</small></div>
      <div className="framing-list" ref={scroll} role="list" aria-label="Сообщения и остатки"><div style={{ height: rows.getTotalSize(),position:'relative' }}>{rows.getVirtualItems().map(row => { const p=items[row.index], r=p.anchor.byte_range; return <button key={p.id} role="listitem" className={`framing-row ${p.kind}`} style={{ height:row.size,transform:`translateY(${row.start}px)` }} onClick={() => onNavigate(p.anchor)}><strong>{p.kind==='message'?'Сообщение':'Остаток'} [{r.start}, {r.end}) · {r.end-r.start} bytes</strong><span>{p.boundary_status==='known'?'Границы по правилу':'Границы не установлены'} · {statuses[p.data_status]}</span><small>{reasons[p.diagnostic] ?? p.diagnostic} · Открыть bytes и источники</small></button> })}</div>{!items.length && <p className="muted p-3">Нет диапазонов в этой загруженной выборке.</p>}</div><More query={pieces} />

    </div>}
    </WorkspaceScreen>
    <WorkspaceScreen active={tab === 'fields'} className="tool-screen">
      {selected.data ? <Suspense fallback={<p className="muted">Загрузка редактора модели…</p>}><InterpretationPanel key={selected.data.id} stream={stream} framing={selected.data} onNavigate={onNavigate} /></Suspense> : <p className="notice">Сначала постройте или выберите сохранённый результат на вкладке «Границы сообщений». Затем опишите поля независимо от границ.</p>}
    </WorkspaceScreen>
  </section>
}
