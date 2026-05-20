import { STATUS } from '../../constants.js'

/**
 * @typedef {{ otpParameters: Object[], version: number, batchSize: number, batchIndex: number, batchId: number }} MigrationPayload
 *
 * @typedef {{ status: 'ready', otpParameters: Object[] }} BatchReady
 * @typedef {{ status: 'incomplete-batch', expected: number, received: number, batchId: number }} BatchIncomplete
 * @typedef {BatchReady | BatchIncomplete} BatchResult
 */

/**
 * @param {Map<number, MigrationPayload>} items - batchIndex → payload
 * @param {number} batchSize
 * @param {number} batchId
 * @returns {BatchResult}
 */
function resolveBatch(items, batchSize, batchId) {
  if (items.size < batchSize) {
    return {
      status: STATUS.incompleteBatch,
      expected: batchSize,
      received: items.size,
      batchId
    }
  }

  const allParams = []
  for (let i = 0; i < batchSize; i++) {
    const payload = items.get(i)
    if (!payload) {
      return {
        status: STATUS.incompleteBatch,
        expected: batchSize,
        received: items.size,
        batchId
      }
    }
    allParams.push(...payload.otpParameters)
  }

  return { status: STATUS.ready, otpParameters: allParams }
}

/**
 * Groups decoded migration payloads by batchId and verifies completeness.
 *
 * Returns a ready result only when every QR code in the batch is present.
 * Partial batches return an incomplete-batch result with no records.
 *
 * @param {MigrationPayload[]} payloads
 * @returns {BatchResult}
 */
export function aggregateBatches(payloads) {
  if (!Array.isArray(payloads) || payloads.length === 0) {
    throw new Error('aggregateBatches: payloads must be a non-empty array')
  }

  /** @type {Map<number, { batchSize: number, items: Map<number, MigrationPayload> }>} */
  const batches = new Map()

  for (const payload of payloads) {
    const { batchId, batchSize, batchIndex } = payload

    if (!batches.has(batchId)) {
      batches.set(batchId, { batchSize, items: new Map() })
    }

    batches.get(batchId).items.set(batchIndex, payload)
  }

  if (batches.size === 1) {
    const [[batchId, { batchSize, items }]] = batches.entries()
    return resolveBatch(items, batchSize, batchId)
  }

  const combined = []
  for (const [batchId, { batchSize, items }] of batches) {
    const result = resolveBatch(items, batchSize, batchId)
    if (result.status !== STATUS.ready) return result
    combined.push(...result.otpParameters)
  }

  return { status: STATUS.ready, otpParameters: combined }
}
