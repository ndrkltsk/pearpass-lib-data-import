/**
 * Normalized OTP record produced by the import pipeline.
 *
 * Field names and values intentionally mirror the OTP config shape used by
 * pearpass-lib-vault-core so imported records can be stored without
 * transformation.
 *
 * @typedef {'SHA1' | 'SHA256' | 'SHA512'} OTPAlgorithm
 * @typedef {'TOTP' | 'HOTP'} OTPType
 *
 * @typedef {Object} OTPRecord
 * @property {string} label       - Account identifier (issuer prefix stripped)
 * @property {string} secret      - Base32-encoded secret
 * @property {OTPType} type       - 'TOTP' or 'HOTP'
 * @property {OTPAlgorithm} algorithm
 * @property {number} digits
 * @property {string} [issuer]
 * @property {number} [period]    - TOTP only
 * @property {number} [counter]   - HOTP only
 * @property {unknown} [raw]      - Original decoded source for auditing
 */
