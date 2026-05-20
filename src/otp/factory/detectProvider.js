import { OTP_PROVIDERS } from '../constants.js'

/**
 * @typedef {import('../constants.js').OTP_PROVIDERS[keyof typeof OTP_PROVIDERS]} OTPProvider
 */

/**
 * Detects which OTP provider/format a URI represents.
 *
 * @param {unknown} input
 * @returns {string}
 */
export function detectProvider(input) {
  if (typeof input !== 'string') return OTP_PROVIDERS.unknown
  if (input.startsWith('otpauth-migration://'))
    return OTP_PROVIDERS.googleMigration
  if (input.startsWith('otpauth://')) return OTP_PROVIDERS.otpUri
  return OTP_PROVIDERS.unknown
}
