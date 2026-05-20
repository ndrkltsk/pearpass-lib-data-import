/**
 * Minimal protobuf encoder used only in tests to build migration payloads.
 * Not part of the public library API.
 */

function encodeVarint(n) {
  const bytes = []
  while (n > 127) {
    bytes.push((n & 0x7f) | 0x80)
    n = Math.floor(n / 128)
  }
  bytes.push(n & 0x7f)
  return bytes
}

function encodeTag(fieldNum, wireType) {
  return encodeVarint(fieldNum * 8 + wireType)
}

function encodeBytes(fieldNum, data) {
  const arr = Array.isArray(data) ? data : Array.from(data)
  return [...encodeTag(fieldNum, 2), ...encodeVarint(arr.length), ...arr]
}

function encodeString(fieldNum, str) {
  const bytes = Array.from(Buffer.from(str, 'utf-8'))
  return encodeBytes(fieldNum, bytes)
}

function encodeVarintField(fieldNum, val) {
  return [...encodeTag(fieldNum, 0), ...encodeVarint(val)]
}

/**
 * @param {{ secret: number[], name?: string, issuer?: string, algorithm?: number, digits?: number, type?: number, counter?: number }} params
 */
function encodeOtpParameters({ secret, name = '', issuer = '', algorithm = 1, digits = 1, type = 2, counter = 0 }) {
  return [
    ...encodeBytes(1, secret),
    ...encodeString(2, name),
    ...(issuer ? encodeString(3, issuer) : []),
    ...encodeVarintField(4, algorithm),
    ...encodeVarintField(5, digits),
    ...encodeVarintField(6, type),
    ...(type === 1 ? encodeVarintField(7, counter) : [])
  ]
}

/**
 * @param {{ otpParams: Object[], version?: number, batchSize?: number, batchIndex?: number, batchId?: number }} opts
 * @returns {Buffer}
 */
export function encodeMigrationPayload({ otpParams = [], version = 1, batchSize = 1, batchIndex = 0, batchId = 1 }) {
  const bytes = []
  for (const p of otpParams) {
    const paramBytes = encodeOtpParameters(p)
    bytes.push(...encodeBytes(1, paramBytes))
  }
  bytes.push(...encodeVarintField(2, version))
  bytes.push(...encodeVarintField(3, batchSize))
  bytes.push(...encodeVarintField(4, batchIndex))
  bytes.push(...encodeVarintField(5, batchId))
  return Buffer.from(bytes)
}

/**
 * @param {Buffer} payload
 * @returns {string}
 */
export function makeGoogleUri(payload) {
  const b64 = payload.toString('base64')
  return `otpauth-migration://offline?data=${encodeURIComponent(b64)}`
}
