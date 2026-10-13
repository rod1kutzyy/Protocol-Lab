import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { components } from '@/shared/api-types'
import { request } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { json, usePages } from './data'
import { ErrorMessage, More } from './Common'

type Hypothesis = components['schemas']['StoredHypothesis']
type Observation = components['schemas']['Observation']
const blank = { statement: '', rationale: '', scope: '', observationIds: [] as string[], unknowns: '', contradictions: '' }
export function HypothesesPanel({ projectId, navigate }: { projectId: string; navigate: (anchor: components['schemas']['StreamRange']) => void }) {
  const client = useQueryClient(), [draft, setDraft] = useState(blank), [parentId, setParentId] = useState<string | null>(null), [selectedId, setSelectedId] = useState<string | null>(null)
  const versions = usePages<Hypothesis>(['hypotheses', projectId], `/projects/${projectId}/hypotheses`)
  const observations = usePages<Observation>(['observations', projectId], `/projects/${projectId}/observations`)
  const selected = useQuery({ queryKey: ['hypothesis', selectedId], queryFn: () => request<Hypothesis>(`/hypotheses/${selectedId}`), enabled: !!selectedId })
  const evidence = useQuery({ queryKey: ['hypothesis-evidence', selectedId], queryFn: () => request<{ items: Observation[] }>(`/hypotheses/${selectedId}/evidence`), enabled: !!selectedId })
  const lines = (text: string) => text.split('\n').map(s => s.trim()).filter(Boolean)
  const save = useMutation({ mutationFn: () => request<Hypothesis>(`/projects/${projectId}/hypotheses`, json({ statement: draft.statement.trim(), rationale: draft.rationale.trim(), scope: draft.scope.trim(), observation_ids: draft.observationIds, unknowns: lines(draft.unknowns), contradictions: lines(draft.contradictions), parent_id: parentId })), onSuccess: h => { setSelectedId(h.id); setParentId(h.id); client.setQueryData(['hypothesis', h.id], h); void client.invalidateQueries({ queryKey: ['hypotheses', projectId] }) } })
  const loaded = observations.data?.pages.flatMap(p => p.items) ?? []
  const items = [...loaded, ...(evidence.data?.items.filter(o => !loaded.some(l => l.id === o.id)) ?? [])]
  const list = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: items.length, getScrollElement: () => list.current, estimateSize: () => 58, overscan: 4 })
  const loadedVersions = versions.data?.pages.flatMap(p => p.items) ?? []
  const options = selected.data && !loadedVersions.some(v => v.id === selectedId) ? [...loadedVersions, selected.data] : loadedVersions
  const card = selected.data
  return <section className="panel stack" aria-label="Семантические гипотезы"><h3>Гипотезы инженера</h3><p className="notice">Гипотеза — предположение о назначении байтов. Passed означает выполнение заданных правил; смысл поля должен обосновывать инженер. Проверка корпуса не подтверждает гипотезу автоматически.</p>
    <form onSubmit={e => { e.preventDefault(); save.mutate() }}><fieldset disabled={save.isPending} className="stack">
      <label>Формулировка гипотезы<textarea value={draft.statement} onChange={e => setDraft({ ...draft, statement: e.target.value })} maxLength={10000} required rows={2} /></label>
      <label>Основания и рассуждение<textarea value={draft.rationale} onChange={e => setDraft({ ...draft, rationale: e.target.value })} maxLength={10000} required rows={2} /></label>
      <label>Область применимости<textarea value={draft.scope} onChange={e => setDraft({ ...draft, scope: e.target.value })} maxLength={10000} required rows={2} /></label>
      <h4>Наблюдения, на которые опирается гипотеза</h4><p className="muted text-xs">Выбрано {draft.observationIds.length}. Наблюдения сохраняют исходные stream/source anchors.</p>
      <div ref={list} className="hypothesis-evidence-list" role="list" aria-label="Выбор наблюдений"><div style={{ height: rows.getTotalSize(), position: 'relative' }}>{rows.getVirtualItems().map(row => { const o = items[row.index], active = draft.observationIds.includes(o.id); return <button type="button" role="listitem" aria-pressed={active} className={`framing-row ${active ? 'selected' : ''}`} key={o.id} style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => setDraft({ ...draft, observationIds: active ? draft.observationIds.filter(id => id !== o.id) : [...draft.observationIds, o.id] })}><strong>{active ? '✓ ' : ''}{o.text}</strong><small>{o.id.slice(0, 8)} · {o.anchors.length} диапазонов</small></button> })}</div>{!items.length && <p className="muted p-3">Создайте наблюдение в панели исходных пакетов.</p>}</div><More query={observations} />
      <div className="form-row"><label>Что неизвестно, по одному пункту<textarea value={draft.unknowns} onChange={e => setDraft({ ...draft, unknowns: e.target.value })} rows={3} /></label><label>Противоречия, по одному пункту<textarea value={draft.contradictions} onChange={e => setDraft({ ...draft, contradictions: e.target.value })} rows={3} /></label></div>
      <div className="form-row"><Button size="sm" disabled={!draft.statement.trim() || !draft.rationale.trim() || !draft.scope.trim()}>Сохранить гипотезу</Button><Button type="button" variant="outline" size="sm" onClick={() => { setDraft(blank); setParentId(null) }}>Новая гипотеза</Button><small className="muted">{parentId ? `Уточнение версии ${parentId.slice(0, 8)}; прежняя версия останется.` : 'Независимая гипотеза.'}</small></div>
    </fieldset></form><ErrorMessage error={save.error ?? versions.error ?? selected.error ?? evidence.error ?? observations.error} />
    <div className="form-row"><label>Сохранённая версия гипотезы<select value={selectedId ?? ''} onChange={e => setSelectedId(e.target.value || null)}><option value="">Выберите гипотезу</option>{options.map(h => <option key={h.id} value={h.id}>{h.statement.slice(0, 60)} · {h.id.slice(0, 8)}</option>)}</select></label><More query={versions} /></div>
    {card && <article className="stack hypothesis-card"><h4>{card.statement}</h4><p><strong>Основания:</strong> {card.rationale}</p><p><strong>Область:</strong> {card.scope}</p><p><strong>Неизвестное:</strong> {card.unknowns.join('; ') || 'Не указано'}</p><p><strong>Противоречия:</strong> {card.contradictions.join('; ') || 'Не указаны'}</p><small>Гипотеза {card.hypothesis_id.slice(0, 8)} · версия {card.id.slice(0, 8)} · {card.created_at}</small><Button size="sm" variant="outline" onClick={() => { setParentId(card.id); setDraft({ statement: card.statement, rationale: card.rationale, scope: card.scope, observationIds: [...card.observation_ids], unknowns: card.unknowns.join('\n'), contradictions: card.contradictions.join('\n') }) }}>Уточнить эту гипотезу</Button>
      <h4>Исходные наблюдения</h4>{evidence.data?.items.map(o => <div key={o.id} className="notice"><p>{o.text}</p><div className="form-row">{o.anchors.map((a, i) => <Button key={i} size="sm" variant="outline" onClick={() => navigate(a)}>К источнику [{a.byte_range.start}, {a.byte_range.end}) · {a.stream_id.slice(0, 8)}</Button>)}</div></div>)}{!card.observation_ids.length && <p className="muted">Ссылки на наблюдения пока не указаны.</p>}
    </article>}
  </section>
}
