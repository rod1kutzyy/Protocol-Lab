import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FolderOpen, Plus } from 'lucide-react'
import { ApiError, request } from '@/shared/api'
import { useSelection } from '@/shared/store'
import { Button } from '@/shared/ui/button'
import { json, usePages, type Project } from './data'
import { ErrorMessage, More } from './Common'
import { RestoreProject } from './PortablePanel'
import { Workspace } from './Workspace'

export function Projects() {
  const { projectId, openProject, forgetProject } = useSelection()
  const [name, setName] = useState('')
  const client = useQueryClient()
  const projects = usePages<Project>(['projects'], '/projects')
  const opened = useQuery({ queryKey: ['project', projectId], queryFn: () => request<Project>(`/projects/${projectId}`), enabled: !!projectId, retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 1 })
  const missing = opened.error instanceof ApiError && opened.error.status === 404
  useEffect(() => { if (missing && projectId) forgetProject(projectId) }, [missing, projectId, forgetProject])
  const create = useMutation({ mutationFn: () => request<Project>('/projects', json({ name: name.trim() })), onSuccess: p => { openProject(p.id); setName(''); void client.invalidateQueries({ queryKey: ['projects'] }) } })
  return <div className="research-layout">
    <aside className="sidebar panel">
      <h2><FolderOpen size={18} /> Проекты</h2>
      <form className="stack" onSubmit={e => { e.preventDefault(); create.mutate() }}>
        <label>Название проекта<input value={name} onChange={e => setName(e.target.value)} maxLength={200} placeholder="Исследование устройства" required /></label>
        <Button size="sm" disabled={!name.trim() || create.isPending}><Plus size={14} />Создать проект</Button>
      </form>
      <RestoreProject />
      <ErrorMessage error={projects.error ?? create.error} />
      <nav aria-label="Проекты" className="project-list">
        {projects.data?.pages.flatMap(p => p.items).map(p => <button key={p.id} aria-current={projectId === p.id ? 'page' : undefined} onClick={() => openProject(p.id)}><strong>{p.name}</strong><small>{p.id.slice(0, 8)}</small></button>)}
      </nav>
      <More query={projects} />
      {projects.data && projects.data.pages.every(p => !p.items.length) && <p className="muted">Создайте первый проект для импорта записи.</p>}
    </aside>
    <div className="min-w-0">
      <ErrorMessage error={missing ? null : opened.error} />
      {opened.data && projectId && !missing ? <Workspace key={projectId} project={opened.data} /> : <div className="panel empty-state"><FolderOpen size={32} /><h2>Откройте или создайте проект</h2><p>Импортируйте PCAP/PCAPNG, выберите соединение и исследуйте исходные байты.</p></div>}
    </div>
  </div>
}
