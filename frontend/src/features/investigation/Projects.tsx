import { useEffect, useRef, useState } from 'react'
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
  const manager = useRef<HTMLDetailsElement>(null)
  const client = useQueryClient()
  const projects = usePages<Project>(['projects'], '/projects')
  const opened = useQuery({ queryKey: ['project', projectId], queryFn: () => request<Project>(`/projects/${projectId}`), enabled: !!projectId, retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 1 })
  const missing = opened.error instanceof ApiError && opened.error.status === 404
  useEffect(() => { if (missing && projectId) forgetProject(projectId) }, [missing, projectId, forgetProject])
  function choose(id: string) { openProject(id); if (manager.current) manager.current.open = false }
  const create = useMutation({ mutationFn: () => request<Project>('/projects', json({ name: name.trim() })), onSuccess: p => { choose(p.id); setName(''); void client.invalidateQueries({ queryKey: ['projects'] }) } })
  const items = projects.data?.pages.flatMap(p => p.items) ?? []
  const options = opened.data && !items.some(p => p.id === opened.data.id) ? [...items, opened.data] : items
  return <div className="project-container">
    <div className="project-toolbar">
      <FolderOpen size={18} aria-hidden="true" />
      <label className="project-picker">Текущий проект<select value={projectId ?? ''} onChange={e => e.target.value && choose(e.target.value)}><option value="">Выберите проект</option>{options.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
      <More query={projects} />
      <details className="project-manager" ref={manager} open={!projectId || undefined}>
        <summary>Проекты</summary>
        <div className="project-manager-content stack">
          <h2>Проекты</h2>
          <form className="stack" onSubmit={e => { e.preventDefault(); create.mutate() }}><label>Название проекта<input value={name} onChange={e => setName(e.target.value)} maxLength={200} placeholder="Исследование устройства" required /></label><Button size="sm" disabled={!name.trim() || create.isPending}><Plus size={14} aria-hidden="true" />Создать проект</Button></form>
          <RestoreProject />
          <ErrorMessage error={create.error} />
        </div>
      </details>
      {opened.data && <span className="muted text-xs project-id">ID {opened.data.id.slice(0, 8)} · локальный проект</span>}
    </div>
    <ErrorMessage error={projects.error ?? (missing ? null : opened.error)} />
    {opened.data && projectId && !missing ? <Workspace key={projectId} project={opened.data} /> : <div className="panel empty-state"><FolderOpen size={32} aria-hidden="true" /><h2>Откройте или создайте проект</h2><p>Импортируйте PCAP/PCAPNG, выберите соединение и исследуйте исходные байты.</p></div>}
  </div>
}
