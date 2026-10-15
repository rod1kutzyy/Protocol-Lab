import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'

const Drafts = createContext<Map<string, unknown> | null>(null)

/** In-memory drafts belong to the opened project, not a transient stream component. */
export function WorkspaceState({ children }: { children: ReactNode }) {
  const [values] = useState(() => new Map<string, unknown>())
  return <Drafts.Provider value={values}>{children}</Drafts.Provider>
}

export function useWorkspaceState<T>(key: string, initial: T | (() => T)) {
  const values = useContext(Drafts)
  const [value, setValue] = useState<T>(() => values?.has(key) ? values.get(key) as T : typeof initial === 'function' ? (initial as () => T)() : initial)
  const latest = useRef(value)
  latest.current = value
  useEffect(() => () => { values?.set(key, latest.current) }, [key, values])
  return [value, setValue] as const
}
