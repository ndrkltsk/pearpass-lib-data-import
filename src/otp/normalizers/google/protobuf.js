/**
 * Minimal protobuf decoder for the Google Authenticator migration payload.
 *
 * Proto schema source
 * Wire types used in this schema:
 *   0 = varint  (int32, enum)
 *   2 = length-delimited  (bytes, string, embedded message)
 *
 * MigrationPayload fields:
 *   1: repeated OtpParameters  otp_parameters
 *   2: int32 version
 *   3: int32 batch_size
 *   4: int32 batch_index
 *   5: int32 batch_id
 *
 * OtpParameters fields:
 *   1: bytes  secret
 *   2: string name      (maps to OTPRecord.label)
 *   3: string issuer
 *   4: int32  algorithm  enum Algorithm    { UNSPECIFIED=0, SHA1=1, SHA256=2, SHA512=3, MD5=4 }
 *   5: int32  digits     enum DigitCount   { UNSPECIFIED=0, SIX=1, EIGHT=2 }
 *   6: int32  type       enum OtpType      { UNSPECIFIED=0, HOTP=1, TOTP=2 }
 *   6: int32  type      (0=unspecified, 1=HOTP, 2=TOTP)
 *   7: int64  counter
 */

const decoder = new TextDecoder()

/**
 * @param {Uint8Array} buf
 * @param {number} offset
 * @returns {{ value: number, offset: number }}
 */
function readVarint(buf, offset) {
  let value = 0
  let shift = 0
  while (offset < buf.length) {
    const b = buf[offset++]
    // Use addition instead of |= to avoid 32-bit sign issues for larger varints
    value += (b & 0x7f) * Math.pow(2, shift)
    shift += 7
    if (!(b & 0x80)) break
  }
  return { value, offset }
}

/**
 * @param {Uint8Array} buf
 * @param {number} offset
 * @returns {{ bytes: Uint8Array, offset: number }}
 */
function readLengthDelimited(buf, offset) {
  const { value: len, offset: dataStart } = readVarint(buf, offset)
  return {
    bytes: buf.slice(dataStart, dataStart + len),
    offset: dataStart + len
  }
}

/**
 * @param {Uint8Array} buf
 * @returns {{ secret: Uint8Array, name: string, issuer: string, algorithm: number, digits: number, type: number, counter: number }}
 */
function decodeOtpParameters(buf) {
  let offset = 0
  const params = {
    secret: new Uint8Array(0),
    name: '',
    issuer: '',
    algorithm: 1,
    digits: 1,
    type: 2,
    counter: 0
  }

  while (offset < buf.length) {
    const { value: tag, offset: after } = readVarint(buf, offset)
    offset = after
    const fieldNumber = Math.floor(tag / 8)
    const wireType = tag & 0x7

    if (wireType === 0) {
      const { value, offset: next } = readVarint(buf, offset)
      offset = next
      if (fieldNumber === 4) params.algorithm = value
      else if (fieldNumber === 5) params.digits = value
      else if (fieldNumber === 6) params.type = value
      else if (fieldNumber === 7) params.counter = value
    } else if (wireType === 2) {
      const { bytes, offset: next } = readLengthDelimited(buf, offset)
      offset = next
      if (fieldNumber === 1) params.secret = bytes
      else if (fieldNumber === 2) params.name = decoder.decode(bytes)
      else if (fieldNumber === 3) params.issuer = decoder.decode(bytes)
    } else {
      break
    }
  }

  return params
}

/**
 * @param {Buffer | Uint8Array} buf
 * @returns {{ otpParameters: Object[], version: number, batchSize: number, batchIndex: number, batchId: number }}
 */
export function decodeMigrationPayload(buf) {
  let offset = 0
  const payload = {
    otpParameters: [],
    version: 0,
    batchSize: 1,
    batchIndex: 0,
    batchId: 0
  }

  while (offset < buf.length) {
    const { value: tag, offset: after } = readVarint(buf, offset)
    offset = after
    const fieldNumber = Math.floor(tag / 8)
    const wireType = tag & 0x7

    if (wireType === 0) {
      const { value, offset: next } = readVarint(buf, offset)
      offset = next
      if (fieldNumber === 2) payload.version = value
      else if (fieldNumber === 3) payload.batchSize = value
      else if (fieldNumber === 4) payload.batchIndex = value
      else if (fieldNumber === 5) payload.batchId = value
    } else if (wireType === 2) {
      const { bytes, offset: next } = readLengthDelimited(buf, offset)
      offset = next
      if (fieldNumber === 1)
        payload.otpParameters.push(decodeOtpParameters(bytes))
    } else {
      break
    }
  }

  return payload
}
