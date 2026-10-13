import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Play, Square } from 'lucide-react'
import { request, terminal, type Job } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'

const JsonPreview = lazy(() => import('@/shared/JsonPreview'))

const labels: Record<Job['status'], string> = {
  queued: 'В очереди', running: 'Выполняется', cancelling: 'Отменяется', committing: 'Сохраняется',
  cancelled: 'Отменена', succeeded: 'Завершена', failed: 'Ошибка',
}

export function JobsPanel() {
  const queryClient = useQueryClient()
  const { jobId, selectJob } = useSelection()
  const [showJson, setShowJson] = useState(false)
  const [connectionError, setConnectionError] = useState<string | null>(null)
  const list = useQuery({ queryKey: ['jobs'], queryFn: () => request<{ items: Job[] }>('/jobs'), refetchInterval: 1000 })
  const selected = useQuery({ queryKey: ['job', jobId], queryFn: () => request<Job>(`/jobs/${jobId}`), enabled: !!jobId })
  const create = useMutation({
    mutationFn: () => request<Job>('/jobs/diagnostic', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ steps: 30, delay_ms: 100 }) }),
    onSuccess: (job) => { queryClient.setQueryData(['job', job.id], job); selectJob(job.id); void queryClient.invalidateQueries({ queryKey: ['jobs'] }) },
  })
  const cancel = useMutation({
    mutationFn: () => request<Job>(`/jobs/${jobId}/cancel`, { method: 'POST' }),
    onSuccess: (job) => { queryClient.setQueryData<Job>(['job', job.id], (previous) => !previous || job.revision >= previous.revision ? job : previous); void queryClient.invalidateQueries({ queryKey: ['jobs'] }) },
  })
  useEffect(() => {
    if (!jobId) return
    setConnectionError(null)
    const events = new EventSource(`/api/v1/jobs/${jobId}/events`)
    events.addEventListener('job', (event: MessageEvent<string>) => {
      const job = JSON.parse(event.data) as Job
      queryClient.setQueryData<Job>(['job', job.id], (previous) => !previous || job.revision >= previous.revision ? job : previous)
      setConnectionError(null)
      if (terminal(job.status)) { events.close(); void queryClient.invalidateQueries({ queryKey: ['jobs'] }) }
    })
    events.onerror = () => {
      setConnectionError('Соединение SSE прервано. Повторное подключение…')
      void queryClient.invalidateQueries({ queryKey: ['job', jobId] })
    }
    return () => events.close()
  }, [jobId, queryClient])

  const scroll = useRef<HTMLDivElement>(null)
  const jobs = [...(list.data?.items ?? [])].reverse()
  const rows = useVirtualizer({ count: jobs.length, getScrollElement: () => scroll.current, estimateSize: () => 64, overscan: 5 })
  const job = selected.data
  const error = create.error ?? cancel.error ?? list.error ?? selected.error
  return <section className="space-y-5" aria-labelledby="jobs-title">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 id="jobs-title" className="text-xl font-semibold">Фоновые задачи</h2><p className="text-sm text-muted-foreground">Импорт, восстановление TCP и диагностика рабочего процесса, прогресс и отмена.</p></div>
      <Button onClick={() => create.mutate()} disabled={create.isPending}><Play size={16} />Запустить диагностику</Button>
    </div>
    {error && <p role="alert" className="text-destructive">{error.message}</p>}
    <div className="grid gap-5 lg:grid-cols-[300px_1fr]">
      <div ref={scroll} className="h-72 overflow-auto rounded-lg border bg-card" aria-label="Список задач">
        {jobs.length === 0 && <p className="p-5 text-sm text-muted-foreground">Задач пока нет.</p>}
        <div style={{ height: rows.getTotalSize(), position: 'relative' }}>
          {rows.getVirtualItems().map((row) => {
            const item = jobs[row.index]
            return <button key={item.id} onClick={() => selectJob(item.id)} className={`absolute left-0 top-0 w-full border-b px-4 text-left text-sm ${item.id === jobId ? 'bg-muted' : ''}`} style={{ height: row.size, transform: `translateY(${row.start}px)` }}>
              <span className="block font-mono text-xs text-muted-foreground">{item.id.slice(0, 8)}</span>{labels[item.status]}
            </button>
          })}
        </div>
      </div>
      <div className="min-w-0 rounded-lg border bg-card p-5">
        {job ? <>
          <div className="mb-4 flex items-center justify-between gap-3"><h3 className="font-semibold" data-testid="job-status">{labels[job.status]}</h3>
            <Button variant="outline" size="sm" onClick={() => cancel.mutate()} disabled={terminal(job.status) || job.status === 'cancelling' || job.status === 'committing' || cancel.isPending}><Square size={14} />Отменить</Button></div>
          <progress className="w-full accent-primary" value={job.completed} max={job.total} aria-label="Прогресс задачи" />
          <p className="mt-2 text-sm text-muted-foreground">{job.completed} / {job.total} · {job.message}</p>
          {job.error && <p role="alert" className="mt-2 text-destructive">{job.error}</p>}
          {connectionError && !terminal(job.status) && <p role="status" className="mt-2 text-sm">{connectionError}</p>}
        </> : <p className="text-muted-foreground">Выберите задачу, чтобы посмотреть её состояние.</p>}
      </div>
    </div>
    <details className="rounded-lg border bg-card p-5" onToggle={(event) => setShowJson(event.currentTarget.open)}>
      <summary className="cursor-pointer font-medium">JSON состояния задачи</summary>
      <p className="my-3 text-sm text-muted-foreground">Диагностический просмотр. Редактор протокольной модели появится на этапе 7.</p>
      {showJson && <Suspense fallback={<p>Загрузка локального редактора…</p>}><JsonPreview value={JSON.stringify(job ?? {}, null, 2)} /></Suspense>}
    </details>
  </section>
}
