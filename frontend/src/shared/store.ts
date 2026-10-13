import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Range } from '@/features/investigation/data'
interface Selection {
  jobId: string | null; selectJob: (id: string) => void
  projectId: string | null; captureId: string | null; sessionId: string | null; streamId: string | null
  range: Range | null; reference: Range | null
  openProject: (id: string) => void; selectCapture: (id: string | null) => void
  forgetProject: (id: string) => void
  selectSession: (id: string, stream: string | null) => void
  selectStream: (id: string) => void; selectRange: (range: Range) => void; pin: () => void
}
export const useSelection = create<Selection>()(persist((set, get) => ({
  jobId: null, projectId: null, captureId: null, sessionId: null, streamId: null, range: null, reference: null,
  selectJob: jobId => set({ jobId }),
  openProject: projectId => set({ projectId, captureId: null, sessionId: null, streamId: null, range: null, reference: null }),
  forgetProject: id => set(state => state.projectId === id ? {
    jobId: null, projectId: null, captureId: null, sessionId: null, streamId: null,
    range: null, reference: null,
  } : state),
  selectCapture: captureId => set({ captureId, sessionId: null, streamId: null, range: null }),
  selectSession: (sessionId, streamId) => set({ sessionId, streamId, range: null }),
  selectStream: streamId => set({ streamId, range: null }), selectRange: range => set({ range }),
  pin: () => set({ reference: get().range }),
}), { name: 'protocol-lab-selection', partialize: s => ({ projectId: s.projectId, captureId: s.captureId, sessionId: s.sessionId, streamId: s.streamId, range: s.range, reference: s.reference }) }))
