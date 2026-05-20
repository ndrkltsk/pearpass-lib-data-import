import { encodeBase32 } from '../../shared/base32.js'
import { OTP_TYPE, OTP_ALGORITHM } from '../../constants.js'

/** @typedef {import('../../interfaces/OTPRecord.js').OTPRecord} OTPRecord */

const ALGORITHM_MAP = {
  0: OTP_ALGORITHM.SHA1,
  1: OTP_ALGORITHM.SHA1,
  2: OTP_ALGORITHM.SHA256,
  3: OTP_ALGORITHM.SHA512
}

const DIGITS_MAP = {
  0: 6,
  1: 6,
  2: 8
}

const TYPE_MAP = {
  0: OTP_TYPE.TOTP,
  1: OTP_TYPE.HOTP,
  2: OTP_TYPE.TOTP
}

/**
 * @param {Object} params - decoded OtpParameters from protobuf
 * @returns {OTPRecord}
 */
function mapOtpParameters(params) {
  if (!params.secret || params.secret.length === 0) {
    throw new Error('OTP parameter is missing required field: secret')
  }

  const type = TYPE_MAP[params.type] ?? OTP_TYPE.TOTP
  const algorithm = ALGORITHM_MAP[params.algorithm] ?? OTP_ALGORITHM.SHA1
  const digits = DIGITS_MAP[params.digits] ?? 6
  const secret = encodeBase32(params.secret)

  /** @type {OTPRecord} */
  const record = {
    type,
    label: params.name || '',
    secret,
    algorithm,
    digits,
    raw: params
  }

  if (params.issuer) record.issuer = params.issuer
  if (type === OTP_TYPE.TOTP) record.period = 30
  if (type === OTP_TYPE.HOTP) record.counter = params.counter ?? 0

  return record
}

/**
 * Converts decoded MigrationPayload OTP parameters into OTPRecord[].
 * @param {{ otpParameters: Object[] }} payload
 * @returns {OTPRecord[]}
 */
export function normalizeGooglePayload(payload) {
  return payload.otpParameters.map(mapOtpParameters)
}
