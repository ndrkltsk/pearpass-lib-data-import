import { OTP_TYPE, OTP_ALGORITHM } from '../constants.js'

/** @typedef {import('../interfaces/OTPRecord.js').OTPRecord} OTPRecord */

const VALID_ALGORITHMS = new Set(Object.values(OTP_ALGORITHM))
const VALID_URI_TYPES = new Set(['totp', 'hotp'])

/**
 * Parses an otpauth:// URI into an OTPRecord.
 *
 * Output shape mirrors the OTP config used by pearpass-lib-vault-core:
 * - type is uppercase ('TOTP' | 'HOTP')
 * - algorithm, digits, and period/counter are always populated with defaults
 * - issuer:account label prefix is stripped; account name becomes `label`
 *
 * @param {string} uri
 * @returns {OTPRecord}
 */
export function parseOtpUri(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('otpauth://')) {
    throw new Error('Invalid OTP URI: must start with otpauth://')
  }

  let url
  try {
    url = new URL(uri)
  } catch {
    throw new Error('Invalid OTP URI: malformed URL')
  }

  const uriType = url.host
  if (!VALID_URI_TYPES.has(uriType)) {
    throw new Error(`Invalid OTP type: "${uriType}". Must be "totp" or "hotp"`)
  }

  const rawLabel = decodeURIComponent(url.pathname.slice(1))
  if (!rawLabel) {
    throw new Error('Invalid OTP URI: missing label')
  }

  const secret = url.searchParams.get('secret')
  if (!secret) {
    throw new Error('Invalid OTP URI: missing required parameter "secret"')
  }

  let label = rawLabel
  let issuer = url.searchParams.get('issuer') ?? undefined

  // Strip "issuer:account" label prefix — the account part is the meaningful label.
  // If no issuer param is present, the prefix becomes the issuer.
  if (rawLabel.includes(':')) {
    const colonIdx = rawLabel.indexOf(':')
    const prefix = rawLabel.slice(0, colonIdx).trim()
    label = rawLabel.slice(colonIdx + 1).trim()
    if (!issuer && prefix) issuer = prefix
  }

  const algorithmRaw = url.searchParams.get('algorithm')?.toUpperCase()
  if (algorithmRaw && !VALID_ALGORITHMS.has(algorithmRaw)) {
    throw new Error(
      `Invalid algorithm: "${algorithmRaw}". Must be SHA1, SHA256, or SHA512`
    )
  }

  const type = uriType === 'totp' ? OTP_TYPE.TOTP : OTP_TYPE.HOTP
  const algorithm = algorithmRaw || OTP_ALGORITHM.SHA1

  const digitsRaw = url.searchParams.get('digits')
  const digits = digitsRaw !== null ? parseInt(digitsRaw, 10) : 6

  const periodRaw = url.searchParams.get('period')
  const counterRaw = url.searchParams.get('counter')

  /** @type {OTPRecord} */
  const record = {
    type,
    label,
    secret: secret.toUpperCase().replace(/\s+/g, ''),
    algorithm,
    digits
  }

  if (issuer !== undefined) record.issuer = issuer

  if (type === OTP_TYPE.TOTP) {
    record.period = periodRaw !== null ? parseInt(periodRaw, 10) : 30
  } else {
    record.counter = counterRaw !== null ? parseInt(counterRaw, 10) : 0
  }

  return record
}
