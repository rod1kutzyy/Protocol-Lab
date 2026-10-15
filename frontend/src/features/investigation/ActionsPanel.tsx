import { useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { components } from '@/shared/api-types'
import { request } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { anchor, formatTime, json, usePages, type Action, type Link, type Session, type Stream } from './data'
import { ErrorMessage, More } from './Common'

export function ActionsPanel({ projectId, onNavigate }: { projectId: string; onNavigate: () => void }) {
  const state = useSelection()
  const [timeOnly, setTimeOnly] = useState(false), [windowMs, setWindowMs] = useState('0')
  const [selected, setSelected] = useState<Action | null>(null), [note, setNote] = useState(''), [linkError, setLinkError] = useState<Error | null>(null)
  const client = useQueryClient()
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
  const openLink = useMutation({ mutationFn: async (link: Link) => { const a = link.observation.anchors[0]; if (!a) throw new Error('В привязке нет диапазона'); const stream = await request<Stream>(`/streams/${a.stream_id}`); const session = await request<Session>(`/sessions/${stream.session_id}`); if (useSelection.getState().projectId !== projectId) return; state.selectCapture(session.capture_id); state.selectSession(session.id, stream.id); state.selectRange({ streamId: stream.id, version: a.reconstruction_version, start: a.byte_range.start, end: a.byte_range.end }); setLinkError(null); onNavigate() }, onError: e => setLinkError(e) })
  return <section className="panel stack" aria-labelledby="actions-title"><h3 id="actions-title">Журнал действий</h3><p className="muted text-xs">Импорт и поправка часов — в разделе «Данные». Выберите действие, чтобы связать его с выделенными байтами.</p>
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
