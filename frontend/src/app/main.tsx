import React, { useState } from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { Projects } from '@/features/investigation/Projects'
import { JobsPanel } from '@/features/jobs/JobsPanel'
import { request, type Health } from '@/shared/api'
import './styles.css'

const client = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 1000 } } })
function App() {
  const [tab, setTab] = useState<'research' | 'jobs'>('research')
  const health = useQuery({ queryKey: ['health'], queryFn: () => request<Health>('/health'), refetchInterval: 5000 })
  return <main className="mx-auto max-w-[1600px] px-5 py-6">
    <header className="mb-10 flex flex-wrap items-center justify-between gap-5 border-b pb-7">
      <div className="flex items-center gap-3"><svg className="text-primary shrink-0" width="32" height="32" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="currentColor" d="m17.425 3.92l-3.76 5.58c-.257.385.244.835.604.52l3.28-3.214c.095-.083.236-.026.236.115v10.062c0 .135-.18.192-.256.096L6.754 3.681a1.85 1.85 0 0 0-1.459-.68C4.138 3 3 3.584 3 4.922V19.07a1.922 1.922 0 0 0 3.555 1.003l3.754-5.58c.257-.385-.238-.835-.598-.52l-3.26 3.279c-.096.083-.237.026-.237-.117V7.101c0-.14.18-.192.257-.096L17.226 20.32c.36.444.9.681 1.46.681C19.848 21 21 20.421 21 19.078V4.93a1.93 1.93 0 0 0-3.575-1.003z" /></svg><div><h1 className="text-2xl font-semibold tracking-tight">Protocol Lab</h1><p className="text-sm text-muted-foreground">Лаборатория исследования TCP-протоколов</p></div></div>
      <span role="status" className="rounded-full border bg-card px-3 py-1 text-sm">{health.isError ? 'API недоступен' : health.data ? `API подключён · v${health.data.version}` : 'Подключение к API…'}</span>
    </header>
    <nav className="app-tabs" aria-label="Разделы приложения"><button aria-pressed={tab === 'research'} onClick={() => setTab('research')}>Исследование</button><button aria-pressed={tab === 'jobs'} onClick={() => setTab('jobs')}>Задачи</button><span>Этап 10 · Надёжность и воспроизводимость</span></nav>
    {tab === 'research' ? <Projects /> : <JobsPanel />}
  </main>
}
ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><QueryClientProvider client={client}><App /></QueryClientProvider></React.StrictMode>)
