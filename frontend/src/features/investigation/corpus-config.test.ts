import { describe, expect, it } from 'vitest'
import { corpusSpec, draftFromCorpus, emptyCorpus } from './corpus-config'
import type { components } from '@/shared/api-types'
describe('explicit corpus selection', () => {
  it('preserves port zero, exact nanoseconds and sorted explicit capture IDs', () => {
    const spec = corpusSpec({ ...emptyCorpus, captureIds: ['b', 'a', 'a'], port: '0', startNs: '1700000000000000001', endNs: '1700000000000000002', direction: 'a_to_b' })
    expect(spec).toEqual({ capture_ids: ['a', 'b'], port: 0, address: null, direction: 'a_to_b', start_ns: '1700000000000000001', end_ns: '1700000000000000002' })
  })
  it('does not round saved filters when loading them in the editor', () => {
    const corpus = { name: 'Exact', spec: { capture_ids: ['id'], start_ns: '-1000000000000000001', end_ns: '1000000000000000001', direction: 'both', port: 0, address: null } } as components['schemas']['StoredCorpus']
    expect(corpusSpec(draftFromCorpus(corpus))).toEqual(corpus.spec)
  })
  it('rejects empty scope, invalid IPv4, port and reversed times', () => {
    expect(() => corpusSpec(emptyCorpus)).toThrow()
    for (const extra of [{ address: '192.0.02.1' }, { port: '65536' }, { startNs: '20', endNs: '10' }, { startNs: '1.1' }]) expect(() => corpusSpec({ ...emptyCorpus, captureIds: ['id'], ...extra })).toThrow()
  })
})
