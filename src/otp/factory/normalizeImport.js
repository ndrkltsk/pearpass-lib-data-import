import { detectProvider } from './detectProvider.js'
import { parseOtpUri } from '../shared/parseOtpUri.js'
import { decodeMigrationUri } from '../normalizers/google/decodeMigration.js'
import { aggregateBatches } from '../normalizers/google/batch.js'
import { normalizeGooglePayload } from '../normalizers/google/normalize.js'
import { OTP_PROVIDERS, STATUS } from '../constants.js'

/**
 * @typedef {import('../interfaces/OTPRecord.js').OTPRecord} OTPRecord
 *
 * @typedef {{ status: 'complete', records: OTPRecord[] }} NormalizeComplete
 * @typedef {{ status: 'incomplete-batch', expected: number, received: number, batchId: number }} NormalizeIncomplete
 * @typedef {NormalizeComplete | NormalizeIncomplete} NormalizeResult
 */

/**
 * Provider-agnostic entry point for importing OTP records.
 *
 * Accepts one or more decoded QR/URI strings. For Google Authenticator
 * batch exports, pass all QR payloads together — the function assembles
 * them and returns incomplete-batch when parts are still missing.
 *
 * @param {string | string[]} input - One or more OTP URI strings
 * @returns {NormalizeResult}
 */
export function normalizeImport(input) {
  const uris = Array.isArray(input) ? input : [input]

  if (uris.length === 0) {
    throw new Error('normalizeImport: input must not be empty')
  }

  const provider = detectProvider(uris[0])

  if (provider === OTP_PROVIDERS.googleMigration) {
    const payloads = uris.map(decodeMigrationUri)
    const batchResult = aggregateBatches(payloads)

    if (batchResult.status !== STATUS.ready) {
      return batchResult
    }

    const records = normalizeGooglePayload({ otpParameters: batchResult.otpParameters })
    return { status: STATUS.complete, records }
  }

  if (provider === OTP_PROVIDERS.otpUri) {
    const records = uris.map(parseOtpUri)
    return { status: STATUS.complete, records }
  }

  throw new Error(`normalizeImport: unsupported or unrecognized input format`)
}
