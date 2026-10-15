import { createContext, useContext, useLayoutEffect, useRef, type ReactNode, type UIEvent } from 'react'

const Visibility = createContext(true)
export const useScreenVisible = () => useContext(Visibility)

/** Keep forms/editors alive and restore native + virtual-list scroll on return. */
export function WorkspaceScreen({ active, children, className = '', label }: {
  active: boolean; children: ReactNode; className?: string; label?: string
}) {
  const parentVisible = useContext(Visibility)
  const visible = active && parentVisible
  const positions = useRef(new Map<HTMLElement, { top: number; left: number }>())
  useLayoutEffect(() => {
    if (!visible) return
    const restore = () => {
      for (const [element, position] of positions.current) {
        if (element.isConnected) element.scrollTo(position)
        else positions.current.delete(element)
      }
    }
    restore()
    const frame = requestAnimationFrame(restore)
    return () => cancelAnimationFrame(frame)
  }, [visible])
  function remember(event: UIEvent<HTMLDivElement>) {
    if (visible && event.target instanceof HTMLElement) {
      positions.current.set(event.target, { top: event.target.scrollTop, left: event.target.scrollLeft })
    }
  }
  return <Visibility.Provider value={visible}><div hidden={!active} className={`workspace-screen ${className}`} aria-label={label} onScrollCapture={remember}>{children}</div></Visibility.Provider>
}
