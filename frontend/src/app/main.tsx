import React, { useState } from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { Activity, Network, ArrowLeft } from 'lucide-react'
import { Projects } from '@/features/investigation/Projects'
import { JobsPanel } from '@/features/jobs/JobsPanel'
import { JobStatus } from '@/features/investigation/Common'
import { request, terminal, type Health, type Job } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { WorkspaceScreen } from '@/shared/WorkspaceScreen'
import { Button } from '@/shared/ui/button'
import './styles.css'

const client = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 1000 } } })
function App() {
  const [jobs, setJobs] = useState(false)
  const jobId = useSelection(s => s.jobId)
  const health = useQuery({ queryKey: ['health'], queryFn: () => request<Health>('/health'), refetchInterval: 5000 })
  const selectedJob = useQuery({ queryKey: ['job', jobId], queryFn: () => request<Job>(`/jobs/${jobId}`), enabled: !!jobId,
    refetchInterval: query => query.state.data && terminal(query.state.data.status) ? false : 400 })
  return <div className="app-shell">
    <a className="skip-link" href="#project-content" onClick={event => { event.preventDefault(); document.getElementById('project-content')?.focus() }}>Перейти к содержимому</a>
    <header className="app-header">
      <div className="app-brand"><Network size={24} aria-hidden="true" /><h1>Protocol Lab</h1><span className="muted">Исследование TCP-протоколов</span></div>
      <div className="app-header-actions"><span role="status" className={`api-status ${health.isError ? 'text-destructive' : ''}`}>{health.isError ? 'API недоступен' : health.data ? `API подключён · v${health.data.version}` : 'Подключение к API…'}</span><Button size="sm" variant={jobs ? 'default' : 'outline'} aria-pressed={jobs} onClick={() => setJobs(!jobs)}>{jobs ? <ArrowLeft size={15} aria-hidden="true" /> : <Activity size={15} aria-hidden="true" />}{jobs ? 'Вернуться к проекту' : 'Задачи'}</Button></div>
    </header>
    <WorkspaceScreen active={!jobs} className="app-content"><Projects /></WorkspaceScreen>
    <WorkspaceScreen active={jobs} className="jobs-screen" label="Фоновые задачи"><JobsPanel /></WorkspaceScreen>
    <footer className="app-statusbar"><span className="muted text-xs">Локальная рабочая область</span>{selectedJob.data ? <JobStatus job={selectedJob.data} /> : <span className="muted text-xs">Выберите задачу для просмотра прогресса</span>}{selectedJob.error && <span role="alert" className="text-destructive text-xs">Не удалось обновить состояние задачи: {selectedJob.error.message}</span>}</footer>
  </div>
}
ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><QueryClientProvider client={client}><App /></QueryClientProvider></React.StrictMode>)
