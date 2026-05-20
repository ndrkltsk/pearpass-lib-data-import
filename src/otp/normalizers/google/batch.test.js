import { aggregateBatches } from './batch'

function makePayload({ otpParameters = [], batchSize = 1, batchIndex = 0, batchId = 1 } = {}) {
  return { otpParameters, batchSize, batchIndex, batchId, version: 1 }
}

const PARAM_A = { secret: new Uint8Array([1]), name: 'alice' }
const PARAM_B = { secret: new Uint8Array([2]), name: 'bob' }
const PARAM_C = { secret: new Uint8Array([3]), name: 'carol' }

describe('aggregateBatches', () => {
  describe('single QR code (batchSize = 1)', () => {
    it('returns complete when the single payload is present', () => {
      const result = aggregateBatches([makePayload({ otpParameters: [PARAM_A] })])
      expect(result.status).toBe('ready')
      expect(result.otpParameters).toEqual([PARAM_A])
    })

    it('returns complete with multiple entries inside one payload', () => {
      const result = aggregateBatches([
        makePayload({ otpParameters: [PARAM_A, PARAM_B] })
      ])
      expect(result.status).toBe('ready')
      expect(result.otpParameters).toHaveLength(2)
    })
  })

  describe('multi-QR batch (batchSize > 1)', () => {
    it('returns ready when all parts are received', () => {
      const payloads = [
        makePayload({ otpParameters: [PARAM_A], batchSize: 2, batchIndex: 0, batchId: 7 }),
        makePayload({ otpParameters: [PARAM_B], batchSize: 2, batchIndex: 1, batchId: 7 })
      ]
      const result = aggregateBatches(payloads)
      expect(result.status).toBe('ready')
      expect(result.otpParameters).toEqual([PARAM_A, PARAM_B])
    })

    it('preserves order by batchIndex regardless of input order', () => {
      const payloads = [
        makePayload({ otpParameters: [PARAM_B], batchSize: 2, batchIndex: 1, batchId: 7 }),
        makePayload({ otpParameters: [PARAM_A], batchSize: 2, batchIndex: 0, batchId: 7 })
      ]
      const result = aggregateBatches(payloads)
      expect(result.status).toBe('ready')
      expect(result.otpParameters[0]).toBe(PARAM_A)
      expect(result.otpParameters[1]).toBe(PARAM_B)
    })

    it('handles three-part batch', () => {
      const payloads = [
        makePayload({ otpParameters: [PARAM_A], batchSize: 3, batchIndex: 0, batchId: 5 }),
        makePayload({ otpParameters: [PARAM_B], batchSize: 3, batchIndex: 1, batchId: 5 }),
        makePayload({ otpParameters: [PARAM_C], batchSize: 3, batchIndex: 2, batchId: 5 })
      ]
      const result = aggregateBatches(payloads)
      expect(result.status).toBe('ready')
      expect(result.otpParameters).toHaveLength(3)
    })
  })

  describe('incomplete batch', () => {
    it('returns incomplete-batch when parts are missing', () => {
      const payloads = [
        makePayload({ otpParameters: [PARAM_A], batchSize: 2, batchIndex: 0, batchId: 7 })
      ]
      const result = aggregateBatches(payloads)
      expect(result.status).toBe('incomplete-batch')
      expect(result.expected).toBe(2)
      expect(result.received).toBe(1)
      expect(result.batchId).toBe(7)
    })

    it('does not return any records for an incomplete batch', () => {
      const result = aggregateBatches([
        makePayload({ otpParameters: [PARAM_A], batchSize: 3, batchIndex: 0, batchId: 8 }),
        makePayload({ otpParameters: [PARAM_B], batchSize: 3, batchIndex: 1, batchId: 8 })
      ])
      expect(result.status).toBe('incomplete-batch')
      expect(result).not.toHaveProperty('otpParameters')
    })

    it('returns incomplete when batchIndex has gaps', () => {
      const payloads = [
        makePayload({ otpParameters: [PARAM_A], batchSize: 2, batchIndex: 0, batchId: 9 }),
        // batchIndex 1 is missing; supplying batchIndex 2 instead (out of bounds)
        makePayload({ otpParameters: [PARAM_B], batchSize: 2, batchIndex: 2, batchId: 9 })
      ]
      const result = aggregateBatches(payloads)
      expect(result.status).toBe('incomplete-batch')
    })
  })

  describe('edge cases', () => {
    it('throws on empty array', () => {
      expect(() => aggregateBatches([])).toThrow()
    })

    it('throws on non-array input', () => {
      expect(() => aggregateBatches(null)).toThrow()
    })
  })
})
