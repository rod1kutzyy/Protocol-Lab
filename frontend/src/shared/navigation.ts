import { useSyncExternalStore } from 'react'

export const sections = ['data', 'research', 'model', 'validation', 'results'] as const
export type Section = typeof sections[number]
export function sectionFromHash(hash: string): Section {
  const value = hash.replace(/^#/, '')
  return sections.includes(value as Section) ? value as Section : 'data'
}
function subscribe(callback: () => void) {
  window.addEventListener('hashchange', callback)
  return () => window.removeEventListener('hashchange', callback)
}
export function useSection() {
  return useSyncExternalStore(subscribe, () => sectionFromHash(window.location.hash), () => 'data' as Section)
}
export function navigateSection(section: Section) { window.location.hash = section }
