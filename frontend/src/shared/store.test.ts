import { afterEach, expect, test, vi } from 'vitest'

async function selection() {
  vi.resetModules()
  const storage = new Map<string, string>()
  const range = { streamId: 'old-stream', version: 'tcp-v1', start: 0, end: 5 }
  storage.set('protocol-lab-selection', JSON.stringify({ version: 0, state: {
    projectId: 'old-project', captureId: 'old-capture', sessionId: 'old-session',
    streamId: 'old-stream', range, reference: range,
  } }))
  const localStorage = {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
  }
  vi.stubGlobal('window', { localStorage })
  return { store: (await import('./store')).useSelection, storage }
}

afterEach(() => vi.unstubAllGlobals())

test('missing saved project clears dependent selection and persists the reset', async () => {
  const { store, storage } = await selection()
  expect(store.getState().projectId).toBe('old-project')
  store.getState().forgetProject('old-project')
  for (const key of ['projectId', 'captureId', 'sessionId', 'streamId', 'range', 'reference'] as const) {
    expect(store.getState()[key]).toBeNull()
    expect(JSON.parse(storage.get('protocol-lab-selection')!).state[key]).toBeNull()
  }
})

test('late missing-project response does not clear a newly opened project', async () => {
  const { store } = await selection()
  store.getState().openProject('new-project')
  store.getState().selectCapture('new-capture')
  store.getState().forgetProject('old-project')
  expect(store.getState().projectId).toBe('new-project')
  expect(store.getState().captureId).toBe('new-capture')
})
