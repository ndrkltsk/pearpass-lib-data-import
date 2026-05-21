import { parseOtpUri } from '../../shared/parseOtpUri.js'

/** @typedef {import('../../interfaces/OTPRecord.js').OTPRecord} OTPRecord */

/**
 * @param {string} txt - Plain-text JSON export from Proton Authenticator
 * @returns {OTPRecord[]}
 */
export function normalizeProtonAuthenticator(txt) {
  let data
  try {
    data = JSON.parse(txt)
  } catch {
    throw new Error('normalizeProtonAuthenticator: invalid JSON')
  }

  if (!Array.isArray(data?.entries)) {
    throw new Error(
      'normalizeProtonAuthenticator: missing or invalid "entries" array'
    )
  }

  return data.entries.map((entry, index) => {
    const uri = entry?.content?.uri
    if (typeof uri !== 'string' || !uri.startsWith('otpauth://')) {
      throw new Error(
        `normalizeProtonAuthenticator: entry at index ${index} has no valid otpauth:// URI`
      )
    }
    return parseOtpUri(uri)
  })
}
