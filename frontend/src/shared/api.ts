import type { components } from './api-types'
export type Job = components['schemas']['JobSnapshot']
export type Health = components['schemas']['HealthResponse']
export const terminal = (status: Job['status']) => ['succeeded', 'failed', 'cancelled'].includes(status)

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, init)
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new ApiError(typeof body?.detail === 'string' ? body.detail : `API: HTTP ${response.status}`, response.status)
  }
  return response.json() as Promise<T>
}
