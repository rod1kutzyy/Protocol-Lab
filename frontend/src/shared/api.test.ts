import { afterEach, expect, test, vi } from 'vitest'
import { ApiError, request, terminal } from './api'

afterEach(() => vi.unstubAllGlobals())
test('only final states are terminal', () => {
  expect(terminal('cancelling')).toBe(false)
  expect(terminal('queued')).toBe(false)
  expect(terminal('cancelled')).toBe(true)
  expect(terminal('failed')).toBe(true)
  expect(terminal('succeeded')).toBe(true)
})
test('API errors remain actionable', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'Job not found' }), { status: 404 })))
  await expect(request('/jobs/missing')).rejects.toThrow('Job not found')
})

test('API errors preserve status to distinguish missing selection from server failure', async () => {
  for (const status of [404, 503]) {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response(JSON.stringify({ detail: 'Details' }), { status })))
    await expect(request('/projects/id')).rejects.toBeInstanceOf(ApiError)
    await expect(request('/projects/id')).rejects.toMatchObject({ status, message: 'Details' })
  }
})
