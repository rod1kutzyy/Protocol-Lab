import { useWorkspaceState } from '@/shared/WorkspaceState'
import { useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { request } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { anchor, byteKey, formatTime, json, loadBytes, usePages, type Evidence, type Packet, type Range } from './data'
import { ErrorMessage, More } from './Common'
import type { components } from '@/shared/api-types'

export function SourcesPanel({ range, projectId }: { range: Range; projectId: string }) {
  const [page, setPage] = useWorkspaceState(`source:${range.streamId}:${range.version}:${range.start}:${range.end}:page`, 0), [chosen, setChosen] = useWorkspaceState<Evidence | null>(`source:${range.streamId}:${range.version}:${range.start}:${range.end}:chosen`, null), [note, setNote] = useWorkspaceState(`source:${range.streamId}:${range.version}:${range.start}:${range.end}:note`, ''), [rawStart, setRawStart] = useWorkspaceState(`source:${range.streamId}:${range.version}:${range.start}:${range.end}:rawStart`, 0)
  const left = range.start+page*4096, length = Math.min(4096, range.end-left)
  const bytes = useQuery({ queryKey: byteKey(range.streamId, left, length), queryFn: ({ signal }) => loadBytes(range.streamId, left, length, signal) })
  const sources = bytes.data?.blocks.flatMap(block => block.variants.flatMap(variant => variant.sources)) ?? []
  const scroll = useRef<HTMLDivElement>(null)
  const rows = useVirtualizer({ count: sources.length, getScrollElement: () => scroll.current, estimateSize: () => 46, overscan: 5 })
  const packet = useQuery({ queryKey: ['packet', chosen?.packet_id], queryFn: () => request<Packet>(`/packets/${chosen?.packet_id}`), enabled: !!chosen })
  const raw = useQuery({ queryKey: ['packet-bytes', chosen?.packet_id, rawStart], queryFn: () => request<components['schemas']['PacketBytes']>(`/packets/${chosen?.packet_id}/bytes?offset=${rawStart}&length=${Math.min(256, (packet.data?.captured_length ?? 0)-rawStart)}`), enabled: !!packet.data && !!chosen })
  const client = useQueryClient()
  const observations = usePages<components['schemas']['Observation']>(['observations', projectId], `/projects/${projectId}/observations`)
  const save = useMutation({ mutationFn: () => request(`/projects/${projectId}/observations`, json({ text: note, anchors: [anchor(range)] })), onSuccess: () => { setNote(''); void client.invalidateQueries({ queryKey: ['observations', projectId] }) } })
  return <section className="panel stack" aria-label="Происхождение диапазона">
    <h3>Исходные пакеты выделенного диапазона</h3>
    <p className="muted text-xs">Показывается [{left}, {left+length}) из [{range.start}, {range.end}). Все варианты перекрытия и одинаковые передачи сохранены.</p>
    <ErrorMessage error={bytes.error ?? packet.error ?? raw.error} />
    <div className="source-list" ref={scroll}><div style={{ height: rows.getTotalSize(), position: 'relative' }}>{rows.getVirtualItems().map(row => { const source = sources[row.index]; return <button className="source-row" key={row.index} style={{ height: row.size, transform: `translateY(${row.start}px)` }} onClick={() => { setChosen(source); setRawStart(Math.floor(source.packet_offset/256)*256) }}>Пакет #{source.packet_index} · поток [{source.stream.byte_range.start}, {source.stream.byte_range.end}) · payload [{source.packet_payload_range.start}, {source.packet_payload_range.end}) · файл @{source.file_offset}</button> })}</div>{bytes.data && !sources.length && <p className="notice">В диапазоне нет доступных исходных байтов: пропуск или усечение.</p>}</div>
    <div className="form-row"><Button variant="outline" size="sm" disabled={!page} onClick={() => { setPage(page-1); setChosen(null) }}>Предыдущие источники</Button><Button variant="outline" size="sm" disabled={left+length>=range.end} onClick={() => { setPage(page+1); setChosen(null) }}>Следующие источники</Button></div>
    {chosen && packet.data && <div className="notice packet-detail"><h4>Пакет #{packet.data.index}</h4><p>{packet.data.source_ip}:{packet.data.source_port} → {packet.data.destination_ip}:{packet.data.destination_port} · {formatTime(packet.data.timestamp_ns)}</p><p>seq={packet.data.tcp_sequence} · ack={packet.data.tcp_acknowledgment} · flags={packet.data.tcp_flags} · checksum={packet.data.tcp_checksum}</p><p>Файл @{chosen.file_offset} · внутри пакета @{chosen.packet_offset} · внутри payload @{chosen.packet_payload_range.start}</p><p className="text-xs">{packet.data.diagnostics.join('; ') || 'Диагностика пакета: замечаний нет.'}</p><p className="muted text-xs">Исходные bytes пакета [{rawStart}, {rawStart+(raw.data?.length ?? 0)}). Выбранные bytes подсвечены.</p><div className="form-row"><Button size="sm" variant="outline" disabled={!rawStart} onClick={() => setRawStart(Math.max(0, rawStart-256))}>Предыдущие bytes пакета</Button><Button size="sm" variant="outline" disabled={rawStart+256>=packet.data.captured_length} onClick={() => setRawStart(rawStart+256)}>Следующие bytes пакета</Button></div><div className="packet-hex">{raw.data?.data_hex.match(/.{2}/g)?.map((byte, i) => <span key={i} className={rawStart+i>=chosen.packet_offset && rawStart+i<chosen.packet_offset+chosen.packet_payload_range.end-chosen.packet_payload_range.start ? 'selected' : ''}>{byte.toUpperCase()} </span>)}</div></div>}
    <form className="form-row" onSubmit={e => { e.preventDefault(); save.mutate() }}><label className="grow">Наблюдение<textarea value={note} onChange={e => setNote(e.target.value)} maxLength={10000} placeholder="Что видно в байтах?" required /></label><Button size="sm" disabled={!note.trim() || save.isPending || range.end-range.start>65536}>Сохранить наблюдение</Button></form><p className="muted text-xs">Одно наблюдение привязывается к диапазону до 65536 позиций, версии восстановления и исходным пакетам.</p><ErrorMessage error={save.error ?? observations.error} />
    {observations.data?.pages.flatMap(p => p.items).map(o => <p className="observation" key={o.id}>{o.text} <small>{o.anchors.map(a => `[${a.byte_range.start}, ${a.byte_range.end}) · ${a.reconstruction_version}`).join('; ')}</small></p>)}<More query={observations} />
  </section>
}
