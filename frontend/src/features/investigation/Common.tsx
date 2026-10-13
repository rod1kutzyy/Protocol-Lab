import { useMutation } from '@tanstack/react-query'
import { request, terminal, type Job } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { useSelection } from '@/shared/store'

export function ErrorMessage({ error }: { error: unknown }) {
  return error ? <p role="alert" className="notice error">{error instanceof Error ? error.message : String(error)}</p> : null
}
export function More({ query }: { query: { hasNextPage: boolean; isFetchingNextPage: boolean; fetchNextPage: () => unknown } }) {
  return query.hasNextPage ? <Button type="button" size="sm" variant="outline" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>Загрузить ещё</Button> : null
}
const statuses: Record<Job['status'], string> = { queued: 'В очереди', running: 'Выполняется', cancelling: 'Отменяется', committing: 'Сохраняется', succeeded: 'Завершена', failed: 'Ошибка', cancelled: 'Отменена' }
export function JobStatus({ job }: { job?: Job }) {
  const selectJob = useSelection(s => s.selectJob)
  const cancel = useMutation({ mutationFn: () => request(`/jobs/${job?.id}/cancel`, { method: 'POST' }) })
  if (!job) return null
  return <div role="status" className="notice job-notice">
    <button className="link" onClick={() => selectJob(job.id)}>{statuses[job.status]}</button> · {job.completed}/{job.total} · {job.message}
    {job.total > 0 && <progress value={job.completed} max={job.total} aria-label="Прогресс операции" />}
    {!terminal(job.status) && <Button size="sm" variant="outline" disabled={job.status === 'committing' || job.status === 'cancelling' || cancel.isPending} onClick={() => cancel.mutate()}>Отменить операцию</Button>}
    {job.error && <p className="text-destructive">{job.error}</p>}
    {job.status === 'succeeded' && job.result?.outcome === 'already_imported' && <p>Повторный импорт: сохранена исходная запись и её настройки.</p>}
    <ErrorMessage error={cancel.error} />
  </div>
}
