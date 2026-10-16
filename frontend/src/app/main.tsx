import React, { useState } from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Activity, ArrowLeft } from 'lucide-react'
import { Projects } from '@/features/investigation/Projects'
import { JobsPanel } from '@/features/jobs/JobsPanel'
import { WorkspaceScreen } from '@/shared/WorkspaceScreen'
import { Button } from '@/shared/ui/button'
import './styles.css'

const client = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 1000 } } })
function App() {
  const [jobs, setJobs] = useState(false)
  return <div className="app-shell">
    <a className="skip-link" href="#project-content" onClick={event => { event.preventDefault(); document.getElementById('project-content')?.focus() }}>Перейти к содержимому</a>
    <header className="app-header">
      <div className="app-brand"><img src="/favicon.svg?v=2" width={24} height={24} alt="" aria-hidden="true" /><h1>Protocol Lab</h1><span className="muted">Исследование TCP-протоколов</span></div>
      <div className="app-header-actions"><Button size="sm" variant={jobs ? 'default' : 'outline'} aria-pressed={jobs} onClick={() => setJobs(!jobs)}>{jobs ? <ArrowLeft size={15} aria-hidden="true" /> : <Activity size={15} aria-hidden="true" />}{jobs ? 'Вернуться к проекту' : 'Задачи'}</Button></div>
    </header>
    <WorkspaceScreen active={!jobs} className="app-content"><Projects /></WorkspaceScreen>
    <WorkspaceScreen active={jobs} className="jobs-screen" label="Фоновые задачи"><JobsPanel /></WorkspaceScreen>
  </div>
}
ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><QueryClientProvider client={client}><App /></QueryClientProvider></React.StrictMode>)
